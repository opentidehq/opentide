"""The analysis engine: offline query checks, editor diagnostics and the language server.

The engine is Rust, from opentidehq/language-server, compiled into this package
as ``opentide._native`` (``analysis/``, built by ``hatch_build.py``): ``pip
install opentide`` is the one install. This module is opentide's one door to
it: commands, MCP tools and validation import it, never ``opentide._native``
directly, so a damaged install fails in one place, with one message
(:class:`EngineUnavailableError`). A missing engine is an error, never a
skipped check.

Positions are the CLI's: 1-based lines and columns, columns in code points,
``end_column`` exclusive.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Literal

from opentide.core.logging import get_logger
from opentide.validation.query_platforms import (
    OFFLINE_QUERY_LANGUAGES as OFFLINE_QUERY_LANGUAGES,
)
from opentide.validation.query_platforms import (
    OFFLINE_QUERY_PLATFORMS as OFFLINE_QUERY_PLATFORMS,
)

if TYPE_CHECKING:
    from opentide._native import Diagnostic as EngineDiagnostic
    from opentide._native import Workspace

logger = get_logger(__name__)

#: ``failure.code`` (and ``opentide explain`` page) when the engine does not import.
ENGINE_UNAVAILABLE = "engine_unavailable"
REINSTALL_COMMAND = "pip install --force-reinstall opentide"

#: The engine's advisories on an Elastic rule block's settings (elastic-1.0):
#: style, which ``opentide lint`` reports with the query warnings.
ELASTIC_ADVISORY_CODES = frozenset(
    {
        "lookback_zero",
        "lookback_long",
        "threshold_lookback",
        "risk_band",
        "technique_not_enterprise",
    }
)

#: Where the Elastic tenants' stack versions are read from; the engine matches
#: this path's ending, so it is passed as written here.
ELASTIC_CONFIGURATION = ".opentide/configurations/platforms/elastic.toml"

Severity = Literal["error", "warning", "note"]
_SEVERITIES: dict[str, Severity] = {
    "error": "error",
    "warning": "warning",
    "information": "note",
    "hint": "note",
}


class EngineUnavailableError(RuntimeError):
    """The compiled engine does not import: the installation is damaged."""

    code = ENGINE_UNAVAILABLE

    def __init__(self, cause: str) -> None:
        super().__init__(f"The opentide analysis engine does not load: {cause}")
        self.cause = cause

    @property
    def advice(self) -> str:
        return f"reinstall opentide: {REINSTALL_COMMAND}"


@cache
def engine() -> ModuleType:
    """The ``opentide._native`` module. Raises :class:`EngineUnavailableError`."""
    import importlib

    try:
        # Through the import system, not the package attribute, so a module
        # that fails to load (or is hidden in tests) is reported every time.
        return importlib.import_module("opentide._native")
    except ImportError as exc:
        raise EngineUnavailableError(str(exc) or type(exc).__name__) from exc


def engine_versions() -> dict[str, str]:
    """``{"engine": …}``: the version of the language-server crates compiled in."""
    return {"engine": str(engine().ENGINE_VERSION)}


@dataclass(frozen=True)
class Finding:
    """One engine diagnostic, in the CLI's coordinates."""

    code: str
    severity: Severity
    message: str
    line: int
    column: int
    end_line: int
    end_column: int
    field_path: tuple[str, ...] = ()
    suggestion: str | None = None

    @classmethod
    def from_engine(cls, diagnostic: EngineDiagnostic) -> Finding:
        return cls(
            code=diagnostic.code,
            severity=_SEVERITIES.get(diagnostic.severity, "note"),
            message=diagnostic.message,
            line=diagnostic.line,
            column=diagnostic.column,
            end_line=diagnostic.end_line,
            end_column=diagnostic.end_column,
            field_path=tuple(diagnostic.field_path or ()),
            suggestion=diagnostic.suggestion,
        )

    @property
    def single_line_end(self) -> int:
        """``end_column`` on the finding's first line (a frame underlines one line)."""
        if self.end_line == self.line:
            return self.end_column
        return self.column + 1


@dataclass(frozen=True)
class QueryCheck:
    """One query of one object file and what the engine found in it."""

    file_path: Path
    #: The ``configurations`` key the query belongs to; ``None`` for a query
    #: elsewhere in the object (a hunt).
    platform: str | None
    language: str
    field_path: tuple[str, ...]
    line: int
    column: int
    findings: tuple[Finding, ...] = ()

    @property
    def errors(self) -> int:
        return sum(1 for item in self.findings if item.severity == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for item in self.findings if item.severity == "warning")


#: Where the Tide catalog the engine uses comes from: generated by this
#: opentide for the workspace, the workspace's committed files, or the engine's
#: compiled-in snapshot.
CatalogSource = Literal["opentide", "workspace", "bundled"]

#: Overrides where opentide caches the catalogs it generates.
CACHE_DIR_ENV = "OPENTIDE_CACHE_DIR"


@dataclass(frozen=True)
class CatalogState:
    """Which Tide catalog the engine uses for this workspace."""

    source: CatalogSource
    #: The opentide version the catalog was generated from.
    version: str
    #: The workspace catalog directory, when there is a workspace.
    path: Path | None = None
    #: Why a better source was not used: opentide's catalog could not be
    #: generated, or a workspace catalog that exists does not parse.
    problem: str | None = None
    #: Catalog files that exist.
    files: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "opentide": self.version,
            "path": None if self.path is None else str(self.path),
            "problem": self.problem,
        }


def install_workspace_catalog(root: Path | None) -> CatalogState:
    """Install the Tide catalogs the engine checks *root*'s objects with; process-wide.

    This opentide's own catalogs, generated from its models and the
    workspace's configuration (:func:`own_catalog`), so the engine is never
    behind opentide. When they cannot be generated, *root*'s committed
    catalogs (``opentide generate schemas`` output, under
    :data:`opentide.generation.lsp_catalog.CATALOG_DIR`), else the engine's
    bundled ones; :attr:`CatalogState.problem` says why.
    """
    from opentide.generation.lsp_catalog import CATALOG_DIR, DEPRECATIONS_FILE, FIELDS_FILE

    module = engine()
    directory = None if root is None else root / CATALOG_DIR
    present = tuple(
        name
        for name in (FIELDS_FILE, DEPRECATIONS_FILE)
        if directory is not None and (directory / name).is_file()
    )
    own_problem = None
    try:
        own = own_catalog(root)
        module.install_catalog(fields=own[FIELDS_FILE], deprecations=own[DEPRECATIONS_FILE])
    except Exception as exc:  # generating the catalog never fails a command
        own_problem = f"opentide's catalog could not be generated: {type(exc).__name__}: {exc}"
        logger.warning("own_catalog_unavailable", problem=own_problem)
    else:
        return CatalogState(
            source="opentide",
            version=str(module.catalog_version()),
            path=directory,
            files=present,
        )
    state = _install_committed_catalog(module, directory)
    if own_problem is None:
        return state
    problem = own_problem if state.problem is None else f"{own_problem}; {state.problem}"
    return CatalogState(
        source=state.source,
        version=state.version,
        path=state.path,
        problem=problem,
        files=state.files,
    )


def reset_catalog() -> None:
    """Back to the engine's bundled catalogs, as at start-up."""
    module = engine()
    module.install_catalog()
    module.set_default_catalog()


def own_catalog(root: Path | None) -> dict[str, str]:
    """``fields.json`` and ``deprecations.json`` for *root*, generated by this opentide.

    What ``opentide generate schemas`` would write: the models, the bundled
    vocabulary, and the workspace's configuration (log sources, statuses).
    Generating takes about two seconds, so the result is cached under the
    user cache directory (``OPENTIDE_CACHE_DIR`` overrides it), keyed by a
    fingerprint of all three; a cache that cannot be written is skipped.
    """
    from opentide.generation.lsp_catalog import catalog_texts

    directory = _catalog_cache() / _catalog_fingerprint(root)
    cached = {name: _read(directory / name) for name in ("fields.json", "deprecations.json")}
    if all(text is not None for text in cached.values()):
        return {name: text for name, text in cached.items() if text is not None}
    texts = catalog_texts()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        for name, text in texts.items():
            partial = directory / f".{name}.{os.getpid()}"
            partial.write_text(text, encoding="utf-8")
            os.replace(partial, directory / name)
    except OSError as exc:
        logger.debug("own_catalog_not_cached", path=str(directory), error=str(exc))
    return texts


def _catalog_cache() -> Path:
    override = os.environ.get(CACHE_DIR_ENV)
    if override:
        return Path(override) / "lsp-catalogs"
    import platformdirs

    return platformdirs.user_cache_path("opentide") / "lsp-catalogs"


def _catalog_fingerprint(root: Path | None) -> str:
    """What the generated catalogs depend on: this opentide's version and model
    sources, its vocabulary data, and *root*'s configuration files."""
    import hashlib

    import opentide
    from opentide.core.root import get_data_root

    digest = hashlib.sha256(opentide.__version__.encode())
    package = Path(opentide.__file__).parent
    data = get_data_root()
    stamped = [
        *sorted((package / "models").rglob("*.py")),
        *sorted((package / "generation").rglob("*.py")),
        *sorted((data / "vocabulary").rglob("*")),
        *sorted((data / "pins").rglob("*")),
    ]
    for path in stamped:
        if path.is_file():
            stat = path.stat()
            digest.update(f"{path}:{stat.st_mtime_ns}:{stat.st_size}\n".encode())
    if root is not None:
        configuration = root / ".opentide" / "configurations"
        files = [*sorted(configuration.rglob("*")), *sorted(root.glob("*.toml"))]
        for path in files:
            if path.is_file():
                digest.update(f"{path.relative_to(root).as_posix()}\n".encode())
                digest.update(path.read_bytes())
    return digest.hexdigest()[:32]


def _install_committed_catalog(module: ModuleType, directory: Path | None) -> CatalogState:
    """*directory*'s catalogs when they exist and parse, the bundled ones otherwise."""
    from opentide.generation.lsp_catalog import DEPRECATIONS_FILE, FIELDS_FILE

    texts: dict[str, str | None] = {FIELDS_FILE: None, DEPRECATIONS_FILE: None}
    problem = None
    if directory is not None:
        for name in texts:
            try:
                texts[name] = (directory / name).read_text(encoding="utf-8")
            except FileNotFoundError:
                continue
            except (OSError, UnicodeDecodeError) as exc:
                problem = f"cannot read {name}: {exc}"
    present = tuple(name for name, text in texts.items() if text is not None)
    if problem is None and present:
        try:
            module.install_catalog(fields=texts[FIELDS_FILE], deprecations=texts[DEPRECATIONS_FILE])
        except ValueError as exc:
            problem = str(exc)
    if problem is not None or not present:
        module.install_catalog()
    # Either file counts: deprecations.json alone is a workspace catalog too.
    source: CatalogSource = "workspace" if present and problem is None else "bundled"
    if problem:
        logger.debug("workspace_catalog_unused", path=str(directory), problem=problem)
    return CatalogState(
        source=source,
        version=str(module.catalog_version()),
        path=directory,
        problem=problem,
        files=present,
    )


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _configuration_files(root: Path | None) -> list[tuple[str, str]]:
    if root is None:
        return []
    text = _read(root / ELASTIC_CONFIGURATION)
    return [] if text is None else [(ELASTIC_CONFIGURATION, text)]


def object_files(root: Path | None = None) -> list[Path]:
    """Every object file of the workspace: rules, threats and objectives."""
    from opentide.registry.catalogue import catalogue_files
    from opentide.registry.paths import resolve_workspace_paths

    paths = resolve_workspace_paths(workspace=root)
    found: list[Path] = []
    for key in ("threat", "objective", "rule"):
        folder = paths.get(key)
        if folder is not None and Path(folder).is_dir():
            found.extend(catalogue_files(Path(folder)))
    return found


def workspace(root: Path | None, files: Iterable[Path] = ()) -> Workspace:
    """An engine workspace of *files* (object files) and the Elastic configuration."""
    contents = [(str(path), text) for path in files if (text := _read(path)) is not None]
    return engine().Workspace(contents + _configuration_files(root))


@dataclass(frozen=True)
class UnreadableFile:
    """An object file whose queries could not be checked, and why."""

    file_path: Path
    problem: str
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True)
class QueryRun:
    """What :func:`check_queries` checked, and the files it could not read."""

    checks: list[QueryCheck]
    unreadable: list[UnreadableFile]


def _unreadable(path: Path, text: str | None) -> UnreadableFile | None:
    """Why *path* has no query the engine could read: not UTF-8, or not YAML."""
    from opentide.core.io import describe_yaml_error, not_utf8_problem, parse_yaml

    if text is None:
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            return UnreadableFile(path, not_utf8_problem(exc))
        except OSError as exc:
            return UnreadableFile(path, exc.strerror or str(exc))
        return None
    try:
        parse_yaml(text)
    except Exception as exc:
        problem = describe_yaml_error(exc)
        return UnreadableFile(path, problem.problem, problem.line, problem.column)
    return None


def check_queries(
    files: Iterable[Path],
    *,
    root: Path | None,
    platforms: Iterable[str] | None = None,
) -> QueryRun:
    """The queries of each object file in *files*, checked offline.

    *platforms* keeps the queries of those ``configurations`` blocks only;
    ``None`` keeps every query, hunts included. A file that is not UTF-8, or
    not YAML, is listed in :attr:`QueryRun.unreadable` instead of passing
    unchecked.
    """
    wanted = None if platforms is None else frozenset(platforms)
    space = workspace(root)
    checks: list[QueryCheck] = []
    unreadable: list[UnreadableFile] = []
    for path in files:
        text = _read(path)
        reports = [] if text is None else space.analyze_queries(text)
        if not reports:
            # The engine finds no query in a file it cannot parse: say which.
            problem = _unreadable(path, text)
            if problem is not None:
                unreadable.append(problem)
            continue
        for report in reports:
            field_path = tuple(report.field_path)
            platform = field_path[1] if field_path[:1] == ("configurations",) else None
            if wanted is not None and platform not in wanted:
                continue
            checks.append(
                QueryCheck(
                    file_path=path,
                    platform=platform,
                    language=report.language,
                    field_path=field_path,
                    line=report.line,
                    column=report.column,
                    findings=tuple(Finding.from_engine(item) for item in report.diagnostics),
                )
            )
    return QueryRun(checks=checks, unreadable=unreadable)


def check_query(
    text: str, *, language: str, platform: str | None = None, stack: str | None = None
) -> list[Finding]:
    """One query on its own, in its own coordinates."""
    return [
        Finding.from_engine(item)
        for item in engine().analyze_query(text, language, platform=platform, stack=stack)
    ]


#: Extensions of a query file: one query in the language its extension names.
QUERY_FILE_SUFFIXES = (".kql", ".spl", ".esql", ".eql", ".kuery", ".lucene")


def is_query_file(path: Path | str) -> bool:
    """Whether *path* names a query file (by extension), rather than an object file."""
    return Path(path).suffix.lower() in QUERY_FILE_SUFFIXES


def query_file_language(path: Path | str) -> str | None:
    """The language a query file's extension names (``.KQL`` as ``.kql``), else ``None``."""
    path = Path(path)
    if not is_query_file(path):
        return None
    return language_for_path(path.with_suffix(path.suffix.lower()))


def check_query_file(path: Path, *, platform: str | None = None) -> QueryCheck | UnreadableFile:
    """The query in a query file, checked in the language its extension names.

    With *platform*, whose languages include it, with that platform's profile
    (Defender's tables, Carbon Black's Lucene); without, the language alone.
    A file with no query is unreadable: there is nothing to pass.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        from opentide.core.io import not_utf8_problem

        return UnreadableFile(path, not_utf8_problem(exc))
    except OSError as exc:
        return UnreadableFile(path, exc.strerror or str(exc))
    language = query_file_language(path)
    if language is None:  # an extension the engine does not know: a bug in the list above
        return UnreadableFile(path, f"no query language for {path.suffix}")
    if not text.strip():
        return UnreadableFile(path, "it holds no query")
    if platform is not None and language not in OFFLINE_QUERY_LANGUAGES.get(platform, ()):
        platform = None
    return QueryCheck(
        file_path=path,
        platform=platform,
        language=language,
        field_path=(),
        line=1,
        column=1,
        findings=tuple(check_query(text, language=language, platform=platform)),
    )


def check_file(
    space: Workspace, path: Path, text: str, *, language: str | None = None
) -> list[Finding]:
    """What the language server reports for one file (an object or a query file)."""
    return [Finding.from_engine(item) for item in space.analyze(str(path), text, language)]


@dataclass(frozen=True)
class HighlightToken:
    """One highlighted span, as the editor colours it."""

    line: int
    column: int
    end_line: int
    end_column: int
    #: A HighlightSpec capture: ``keyword``, ``function``, ``string``, ...
    capture: str


def highlight(text: str, language: str) -> list[HighlightToken]:
    """The tokens the language server colours in *text*; queries in an object included."""
    return [HighlightToken(*token) for token in engine().highlight(text, language)]


def language_for_path(path: Path | str) -> str | None:
    """``opentide-yaml`` for an object file, a query language for its extension, else ``None``."""
    return engine().language_for_path(str(path))


def describe(code: str) -> str | None:
    """The engine's sentence for *code*, or ``None`` (also when the engine does not load)."""
    try:
        module = engine()
    except EngineUnavailableError:
        return None
    return module.describe_code(code)


def engine_codes() -> Sequence[str]:
    """Every code the engine emits; empty when the engine does not load."""
    try:
        return tuple(engine().CODES)
    except EngineUnavailableError:
        return ()


def serve_stdio() -> None:
    """Serve the language server protocol on stdin and stdout until the client exits."""
    engine().serve_stdio()
