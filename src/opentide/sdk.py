"""The opentide SDK: a Tide workspace, opened once, and what you do with it.

:class:`Workspace` wraps the ``opentide`` Rust crate (the facade, UC-5.1) one to
one, through ``opentide._native.sdk`` (UC-5.2, #837): ``open``, ``validate``,
``lint``, ``info``, ``rules``, ``objectives``, ``threats``, ``catalog``,
``coverage``, ``deploy_plan`` and ``run_json``. The Rust SDK, the npm package
and this module run the same code and hand back the same documents: the
command line's ``--json`` data, keys in its order.

``import opentide`` does not import this module; ``opentide.Workspace`` and
``opentide.run_json`` load it on first use.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar

if TYPE_CHECKING:
    from opentide._native import sdk as _sdk

__all__ = [
    "DeployPlan",
    "LintReport",
    "OpentideError",
    "Validation",
    "Workspace",
    "run_json",
]

#: A JSON document as the command line writes it, parsed.
Document = dict[str, Any]

ValidateCheck = Literal[
    "id-uniqueness", "uuid-format", "schema", "cve", "sharing-config", "configuration", "queries"
]
LintCheckName = Literal["filenames", "metadata", "placeholders", "queries"]
QueriesMode = Literal["error", "warn", "off"]
StrategyName = Literal["PREVIEW", "RELEASE"]

_T = TypeVar("_T")


class OpentideError(Exception):
    """A call the SDK could not run.

    ``code`` is stable: ``configuration_invalid`` or the configuration check's
    own code (``config_parse``, ...), ``io_error``, ``usage_invalid_choice``
    for an option the command line would refuse, ``no_json_document`` when
    :func:`run_json`'s command writes no document (``--version``). Match on the
    code, not the message. Findings about the workspace are not errors: they
    are in the report.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _load() -> None:
    """Loads ``opentide._native`` through the one door to the engine, which
    raises :class:`opentide.analysis.EngineUnavailableError` when it does not load."""
    from opentide.analysis import engine

    engine()


def _call(function: Callable[..., _T], *args: object, **kwargs: object) -> _T:
    """*function*'s result; its ``SdkError`` as :class:`OpentideError`."""
    from opentide._native.sdk import SdkError

    try:
        return function(*args, **kwargs)
    except SdkError as exc:
        code, message = exc.args
        raise OpentideError(str(code), str(message)) from None


@dataclass(frozen=True)
class Validation:
    """What :meth:`Workspace.validate` returns: ``validate --json``'s data.

    ``report`` holds ``issues`` and ``warnings``, each finding with its
    ``code``, ``severity``, ``path``, 1-based ``line`` and ``column``,
    ``field_path``, ``suggestion`` and ``fix``.
    """

    #: Each check that ran, by name: ``{"check": name, "status": ...}``.
    checks: dict[str, dict[str, str]]
    report: Document
    summary: Document
    #: Whether the run fails (an error, or a warning under ``strict``).
    failed: bool
    warned: bool
    #: The command line's exit code for this run.
    exit_code: int


@dataclass(frozen=True)
class LintReport:
    """What :meth:`Workspace.lint` returns: ``lint --json``'s data."""

    path: str
    checks: list[str]
    findings: list[Document]
    #: ``completed``, ``issues`` or ``failed``.
    status: str
    message: str
    exit_code: int
    failure_code: str | None
    summary: Document | None
    outcome: str | None
    unmatched: list[str]
    warnings: list[str]
    next_actions: list[Document]


@dataclass(frozen=True)
class DeployPlan:
    """What :meth:`Workspace.deploy_plan` returns.

    ``document`` is ``deploy --dry-run --json``'s ``result``; ``summary`` its
    counts, when the run planned; ``ok`` whether the dry run completed.
    """

    document: Document
    summary: Document | None
    ok: bool


class Workspace:
    """A Tide workspace: its configuration, resolved once, and every object
    file, read and parsed once into one index.

    Opening is the expensive step; each method then reads the index, so keep
    the ``Workspace`` and call as many methods on it as you need. Methods
    release the GIL while they run.
    """

    __slots__ = ("_inner",)

    def __init__(self, inner: _sdk.Workspace) -> None:
        """Wraps an opened workspace: use :meth:`open` or :meth:`from_files`."""
        self._inner = inner

    @classmethod
    def open(
        cls, path: str | os.PathLike[str], *, cwd: str | os.PathLike[str] | None = None
    ) -> Workspace:
        """Opens the workspace at *path*: a repository holding ``.opentide/``
        or ``objects/``, or a folder inside one. Paths in findings are shown
        from *cwd* (default: the workspace's own folder).

        Raises :class:`OpentideError` (``io_error``, ``configuration_invalid``).
        """
        _load()
        from opentide._native.sdk import Workspace as NativeWorkspace

        return cls(
            _call(
                NativeWorkspace.open,
                os.fspath(path),
                None if cwd is None else os.fspath(cwd),
            )
        )

    @classmethod
    def from_files(cls, root: str | os.PathLike[str], files: Mapping[str, str]) -> Workspace:
        """Opens a workspace held in memory, rooted at *root*: each key of
        *files* is a path (relative to *root*, or absolute), each value its
        text. Nothing is read from or written to the disk."""
        _load()
        from opentide._native.sdk import Workspace as NativeWorkspace

        return cls(_call(NativeWorkspace.from_files, os.fspath(root), list(files.items())))

    @property
    def root(self) -> Path:
        """The workspace folder: the one that holds ``.opentide/`` and ``objects/``."""
        return Path(self._inner.root)

    def validate(
        self,
        *,
        check: ValidateCheck | None = None,
        files: Sequence[str] = (),
        uuids: Sequence[str] = (),
        types: Sequence[str] = (),
        strict: bool = False,
        queries: QueriesMode = "error",
    ) -> Validation:
        """Runs every check of ``opentide validate`` (or *check* alone).

        The options are the command's flags: ``--file``, ``--uuid``,
        ``--type``, ``--strict`` and ``--queries``.
        """
        data = json.loads(
            _call(
                self._inner.validate,
                check=check,
                files=list(files),
                uuids=list(uuids),
                types=list(types),
                strict=strict,
                queries=queries,
            )
        )
        return Validation(**data)

    def lint(
        self,
        *,
        checks: Sequence[LintCheckName] = (),
        files: Sequence[str] = (),
        strict: bool = False,
    ) -> LintReport:
        """Runs ``opentide lint`` (its ``lint.toml``, or *checks*) without
        fixing anything."""
        data = json.loads(
            _call(self._inner.lint, checks=list(checks), files=list(files), strict=strict)
        )
        return LintReport(**data)

    def info(self) -> Document:
        """``opentide info``: the object counts, the files that did not load and
        each platform with its tenants (the variables each reads and whether
        each is set, never their values)."""
        return json.loads(_call(self._inner.info))

    def rules(self) -> list[Document]:
        """The detection rules: their rows of the catalogue (``uuid``, ``type``,
        ``schema``, ``name``, ``path``, ``techniques``, ...), in index order."""
        return json.loads(_call(self._inner.rules))

    def objectives(self) -> list[Document]:
        """The detection objectives: their rows of the catalogue."""
        return json.loads(_call(self._inner.objectives))

    def threats(self) -> list[Document]:
        """The threat vectors: their rows of the catalogue."""
        return json.loads(_call(self._inner.threats))

    def catalog(self) -> Document:
        """``opentide info catalog``: every object with its techniques and
        platforms, every edge, the signals and the ATT&CK matrix."""
        return json.loads(_call(self._inner.catalog))

    def coverage(self, technique: str) -> Document:
        """``opentide info coverage --technique``: the rules that cover the
        ATT&CK *technique*, their own techniques or inherited ones."""
        return json.loads(_call(self._inner.coverage, technique))

    def deploy_plan(
        self,
        *,
        strategies: Sequence[StrategyName] = ("RELEASE",),
        uuids: Sequence[str] = (),
        files: Sequence[str] = (),
        platform: str | None = None,
        keep_deprecated: bool | None = None,
    ) -> DeployPlan:
        """``opentide deploy --dry-run``: the rules the strategies select, the
        tenants each reaches and the request bodies a real run would send.
        Nothing is sent and nothing is written. Without *uuids* or *files* it
        plans every rule file (``--all``)."""
        document, summary, ok = _call(
            self._inner.deploy_plan,
            strategies=list(strategies),
            uuids=list(uuids),
            files=list(files),
            platform=platform,
            keep_deprecated=keep_deprecated,
        )
        return DeployPlan(
            document=json.loads(document),
            summary=None if summary is None else json.loads(summary),
            ok=ok,
        )

    def run_json(self, argv: Sequence[str]) -> Any:
        """:func:`run_json` on this workspace: ``opentide --json --repo
        <root> <argv>``."""
        return run_json(["--repo", str(self.root), *argv])

    def __repr__(self) -> str:
        return f"Workspace({str(self.root)!r})"


def run_json(argv: Sequence[str]) -> Any:
    """Runs ``opentide --json <argv>`` in this process and returns its document:
    the envelope (``ok``, ``command``, ``result``, ``failure``, ...) or, for
    ``commands``, the command tree. A command that fails still returns its
    document, with ``ok: false`` and ``failure.code``.

    It reads the process's environment and working directory as the command
    line does (``--repo`` names a workspace elsewhere) and writes nothing to
    the process's streams. Raises :class:`OpentideError`
    (``no_json_document``) when the command writes no document.
    """
    _load()
    from opentide._native.sdk import run_json as native_run_json

    return json.loads(_call(native_run_json, list(argv)))
