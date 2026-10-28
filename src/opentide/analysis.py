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

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Literal

from opentide.core.logging import get_logger

if TYPE_CHECKING:
    from opentide._native import Diagnostic as EngineDiagnostic
    from opentide._native import Workspace

logger = get_logger(__name__)

#: ``failure.code`` (and ``opentide explain`` page) when the engine does not import.
ENGINE_UNAVAILABLE = "engine_unavailable"
REINSTALL_COMMAND = "pip install --force-reinstall opentide"

#: Platforms whose rule queries the engine checks offline, and their languages.
#: SentinelOne (S1QL) is checked on the tenant only (``validate query --live``).
#: CrowdStrike and HarfangLab are never checked: no fake validation.
OFFLINE_QUERY_LANGUAGES: dict[str, tuple[str, ...]] = {
    "sentinel": ("kql",),
    "defender_for_endpoint": ("kql",),
    "splunk": ("spl",),
    "elastic": ("esql", "eql", "kuery", "lucene"),
    "carbon_black_cloud": ("lucene",),
}
OFFLINE_QUERY_PLATFORMS = frozenset(OFFLINE_QUERY_LANGUAGES)

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


@dataclass(frozen=True)
class CatalogState:
    """Which Tide catalog the engine uses for this workspace."""

    source: Literal["workspace", "bundled"]
    #: The opentide version the catalog was generated from.
    version: str
    #: The workspace catalog directory, when there is a workspace.
    path: Path | None = None
    #: Why a workspace catalog that exists was not used.
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
    """Use *root*'s generated catalogs when they exist, the bundled ones otherwise.

    The catalogs are ``opentide generate schemas`` output
    (:data:`opentide.generation.lsp_catalog.CATALOG_DIR`). One that does not
    parse is reported in :attr:`CatalogState.problem` and the bundled catalogs
    are used; the install is process-wide.
    """
    from opentide.generation.lsp_catalog import CATALOG_DIR, DEPRECATIONS_FILE, FIELDS_FILE

    module = engine()
    directory = None if root is None else root / CATALOG_DIR
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
    source: Literal["workspace", "bundled"] = (
        "workspace" if present and problem is None else "bundled"
    )
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
