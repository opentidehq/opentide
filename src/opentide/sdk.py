"""The opentide SDK: a Tide workspace, opened once, and what you do with it.

:class:`Workspace` wraps the ``opentide`` Rust crate (the facade, UC-5.1) one to
one, through ``opentide._native.sdk`` (UC-5.2, #837): ``open``, ``validate``,
``lint``, ``info``, ``rules``, ``objectives``, ``threats``, ``catalog``,
``coverage``, ``deploy_plan``, ``tenants`` and ``run_json``. The Rust SDK, the
npm package and this module run the same code and hand back the same documents:
the command line's ``--json`` data, keys in its order.

:class:`Connection` wraps the facade's tenant operations (UC-5.2b): a query run,
a live query check and a rule deploy, ``async`` methods that run on the Rust
core's tokio runtime (through pyo3-async-runtimes) without the GIL while the
``asyncio`` event loop awaits them.

``import opentide`` does not import this module; ``opentide.Workspace``,
``opentide.Connection`` and the other names load it on first use. The async
runtime starts on the first tenant operation, never on import.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar

if TYPE_CHECKING:
    from opentide._native import sdk as _sdk

__all__ = [
    "Canceller",
    "Capabilities",
    "Connection",
    "DeployOutcome",
    "DeployPlan",
    "LintReport",
    "LiveCheck",
    "OpentideError",
    "QueryResult",
    "TenantConfig",
    "Validation",
    "Workspace",
    "capabilities",
    "platforms",
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
OperationName = Literal["create", "update", "disable", "delete"]

#: Rows a query returns when the caller names no limit (the command line's).
DEFAULT_LIMIT = 100
#: Seconds an asynchronous search may run when the caller names no timeout.
DEFAULT_TIMEOUT = 120.0
#: The window :meth:`Connection.query` searches when given no *start*:
#: ``opentide query``'s ``--since 24h``.
DEFAULT_SINCE = timedelta(hours=24)

_T = TypeVar("_T")


class OpentideError(Exception):
    """A call the SDK could not run.

    ``code`` is stable: ``configuration_invalid`` or the configuration check's
    own code (``config_parse``, ...), ``io_error``, ``usage_invalid_choice``
    for an option the command line would refuse, ``no_json_document`` when
    :func:`run_json`'s command writes no document (``--version``). A tenant
    operation's codes are the connectors' (``credential_unset``,
    ``tenant_refused``, ``tenant_unreachable``, ``operation_unsupported``,
    ``interrupted``, ...); ``detail`` is then the vendor's own words, when the
    tenant gave a reason. Match on the code, not the message. Findings about
    the workspace are not errors: they are in the report.
    """

    def __init__(self, code: str, message: str, detail: str | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.detail = detail


def _load() -> None:
    """Loads ``opentide._native`` through the one door to the engine, which
    raises :class:`opentide.analysis.EngineUnavailableError` when it does not load."""
    from opentide.analysis import engine

    engine()


def _error(exc: BaseException) -> OpentideError:
    """The ``SdkError`` *exc* as :class:`OpentideError`."""
    code, message, detail = exc.args
    return OpentideError(str(code), str(message), None if detail is None else str(detail))


def _call(function: Callable[..., _T], *args: object, **kwargs: object) -> _T:
    """*function*'s result; its ``SdkError`` as :class:`OpentideError`."""
    from opentide._native.sdk import SdkError

    try:
        return function(*args, **kwargs)
    except SdkError as exc:
        raise _error(exc) from None


async def _document(
    function: Callable[..., Awaitable[str]], *args: object, **kwargs: object
) -> Any:
    """The document *function*'s awaitable resolves to; its ``SdkError`` as
    :class:`OpentideError`, whether the call or the operation raised it."""
    from opentide._native.sdk import SdkError

    try:
        return json.loads(await function(*args, **kwargs))
    except SdkError as exc:
        raise _error(exc) from None


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

    def tenants(self, platform: str) -> list[TenantConfig]:
        """The tenants the workspace configures for *platform* (its
        ``[[tenants]]`` in ``.opentide/configurations/platforms/<platform>.toml``),
        in file order; empty when it configures none. Open one with
        :meth:`Connection.open`."""
        return [TenantConfig._wrap(tenant) for tenant in _call(self._inner.tenants, platform)]

    def run_json(self, argv: Sequence[str]) -> Any:
        """:func:`run_json` on this workspace: ``opentide --json --repo
        <root> <argv>``."""
        return run_json(["--repo", str(self.root), *argv])

    def __repr__(self) -> str:
        return f"Workspace({str(self.root)!r})"


@dataclass(frozen=True)
class Capabilities:
    """What a platform's connector can do: :meth:`Connection.deploy`,
    :meth:`Connection.validate_query` (``validate query --live``) and
    :meth:`Connection.query` (``opentide query``)."""

    deploy: bool
    live_validation: bool
    query: bool


@dataclass(frozen=True)
class QueryResult:
    """What :meth:`Connection.query` returns: at most the request's ``limit``
    rows, each a dict of its columns in the order they came."""

    #: Each column's ``name`` and the vendor's ``type`` (``None`` when it names none).
    columns: list[Document]
    rows: list[Document]
    #: More rows matched than the limit let through.
    truncated: bool
    #: The platform stopped early and says the rows are incomplete.
    partial: bool
    #: The platform's reservations about the result.
    warnings: list[str]
    #: The platform's id of the search (CrowdStrike's job id).
    vendor_query_id: str | None
    #: What was sent, when the connector changed the query (a limit it added).
    sent: str | None
    #: The language the connector used.
    language: str | None


@dataclass(frozen=True)
class LiveCheck:
    """What :meth:`Connection.validate_query` returns for a query the tenant
    accepted. ``errors`` are why validation still fails it (Defender's
    required columns); a query the tenant refuses raises ``tenant_refused``."""

    #: The search's answer, when the check ran one.
    result: QueryResult | None
    errors: list[str]
    warnings: list[str]


@dataclass(frozen=True)
class DeployOutcome:
    """What :meth:`Connection.deploy` did."""

    #: The platform's identifier of the rule, which a deploy keeps in its state.
    remote_id: str | None
    operation: OperationName


def _capabilities(flags: tuple[bool, bool, bool]) -> Capabilities:
    deploy, live_validation, query = flags
    return Capabilities(deploy=deploy, live_validation=live_validation, query=query)


def _query_result(data: Document) -> QueryResult:
    return QueryResult(**data)


def _instant(at: datetime) -> str:
    """*at* as an RFC 3339 instant; a naive datetime is taken as UTC."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return at.isoformat()


def platforms() -> list[str]:
    """The platforms with a connector, in the order opentide lists them."""
    _load()
    from opentide._native.sdk import platforms as native_platforms

    return native_platforms()


def capabilities(platform: str) -> Capabilities | None:
    """What the connector of *platform* can do; ``None`` for a platform without one."""
    _load()
    from opentide._native.sdk import capabilities as native_capabilities

    flags = native_capabilities(platform)
    return None if flags is None else _capabilities(flags)


class TenantConfig:
    """A tenant: its platform, its name and its ``setup`` (``$NAME`` values
    unresolved until it connects). :meth:`Workspace.tenants` reads them from the
    workspace; construct one to configure a tenant in code."""

    __slots__ = ("_inner",)

    def __init__(self, platform: str, name: str, setup: Mapping[str, str]) -> None:
        """The tenant *name* of *platform*; each value of *setup* is a string, a
        ``$NAME`` one read from the environment when it connects."""
        _load()
        from opentide._native.sdk import TenantConfig as NativeTenantConfig

        self._inner = NativeTenantConfig(platform, name, list(setup.items()))

    @classmethod
    def _wrap(cls, inner: _sdk.TenantConfig) -> TenantConfig:
        tenant = cls.__new__(cls)
        tenant._inner = inner
        return tenant

    @property
    def platform(self) -> str:
        """The platform's identifier (``splunk``, ``sentinel_one``)."""
        return self._inner.platform

    @property
    def name(self) -> str:
        """The tenant's name."""
        return self._inner.name

    @property
    def setup_keys(self) -> list[str]:
        """The keys of its ``setup``, in name order; never their values."""
        return self._inner.setup_keys

    def __repr__(self) -> str:
        return f"TenantConfig({self.platform!r}, {self.name!r})"


class Canceller:
    """Cancels a :class:`Connection`'s operations from elsewhere: the one
    running raises ``interrupted``, and so does every later one."""

    __slots__ = ("_inner",)

    def __init__(self, inner: _sdk.Canceller) -> None:
        """Wraps a connection's canceller: use :meth:`Connection.canceller`."""
        self._inner = inner

    def cancel(self) -> None:
        """Cancels."""
        self._inner.cancel()

    @property
    def is_cancelled(self) -> bool:
        """Whether :meth:`cancel` was called."""
        return self._inner.is_cancelled


class Connection:
    """One tenant's client, built from that tenant's own settings (TLS, CA
    bundle, proxy, timeout, credentials). Secrets never reach a message or a
    ``repr``.

    ``query``, ``validate_query`` and ``deploy`` are ``async``: each runs on the
    Rust core's tokio runtime without the GIL while the event loop awaits it.
    Cancelling the task that awaits one stops it, and a search it stops waiting
    for is stopped on the tenant where the API allows it. One connection serves
    many operations, at once or in turn.
    """

    __slots__ = ("_inner",)

    def __init__(self, inner: _sdk.Connection) -> None:
        """Wraps an opened connection: use :meth:`open`."""
        self._inner = inner

    @classmethod
    def open(
        cls,
        tenant: TenantConfig,
        *,
        environment: Mapping[str, str] | None = None,
        proxy: str | None = None,
        timeout: float | None = None,
    ) -> Connection:
        """Connects to *tenant*: resolves its credentials and builds its client.
        Nothing is sent until an operation runs.

        *environment* replaces the process's environment for the tenant's
        ``$NAME`` credentials, CA bundles and proxies; *proxy* is used before
        the environment's; *timeout* is how long, in seconds, the tenant may
        take to answer a read (Elastic, Splunk, Carbon Black Cloud, Sentinel).

        Raises :class:`OpentideError` (``credential_unset``,
        ``tenant_setup_invalid``, ``operation_unsupported``).
        """
        _load()
        from opentide._native.sdk import Connection as NativeConnection

        return cls(
            _call(
                NativeConnection.open,
                tenant._inner,
                environment=None if environment is None else list(environment.items()),
                proxy=proxy,
                timeout=timeout,
            )
        )

    @property
    def platform(self) -> str:
        """The platform's identifier."""
        return self._inner.platform

    @property
    def tenant(self) -> str:
        """The tenant's name."""
        return self._inner.tenant

    @property
    def capabilities(self) -> Capabilities:
        """What this tenant's connector can do."""
        return _capabilities(self._inner.capabilities)

    def canceller(self) -> Canceller:
        """A handle that cancels this connection's operations from elsewhere
        (another task, a signal handler)."""
        return Canceller(self._inner.canceller())

    async def query(
        self,
        text: str,
        language: str = "",
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
        index: Sequence[str] = (),
        data_view: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> QueryResult:
        """Runs *text* on the tenant (``opentide query``) over *start* to *end*
        (default: the 24 hours before now) and returns at most *limit* rows.
        Nothing is saved on the tenant.

        *language* is the query's (``kql``, ``esql``, ``s1ql``); empty takes the
        platform's first. *index* is the Elastic indices, the HarfangLab
        telemetry source or the CrowdStrike repository; *data_view* Elastic's;
        *timeout* how long, in seconds, an asynchronous search may run. A naive
        datetime is taken as UTC.

        Raises :class:`OpentideError` (``tenant_refused``, ``query_timed_out``,
        ``tenant_unreachable``, ``authentication_failed``, ``interrupted``,
        ``operation_unsupported``, ...).
        """
        end = end or datetime.now(timezone.utc)
        start = start or end - DEFAULT_SINCE
        data = await _document(
            self._inner.query,
            text,
            language,
            start=_instant(start),
            end=_instant(end),
            limit=limit,
            index=list(index),
            data_view=data_view,
            timeout=timeout,
        )
        return _query_result(data)

    async def validate_query(
        self,
        text: str,
        language: str = "",
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = DEFAULT_LIMIT,
        index: Sequence[str] = (),
        data_view: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> LiveCheck:
        """Checks *text* on the tenant (``opentide validate query --live``): by
        default a search for one row over the minute before *end* (now). The
        options are :meth:`query`'s.

        Raises :class:`OpentideError`: ``tenant_refused`` for a query the
        tenant refuses (the vendor's words in ``detail``), the other codes of
        :meth:`query`, and ``operation_unsupported`` on a platform that cannot
        check a query live (CrowdStrike, HarfangLab, Sysdig): never a faked
        verdict.
        """
        data = await _document(
            self._inner.validate_query,
            text,
            language,
            start=None if start is None else _instant(start),
            end=None if end is None else _instant(end),
            limit=limit,
            index=list(index),
            data_view=data_view,
            timeout=timeout,
        )
        result = data["result"]
        return LiveCheck(
            result=None if result is None else _query_result(result),
            errors=data["errors"],
            warnings=data["warnings"],
        )

    async def deploy(self, rule_id: str, operation: OperationName, body: bytes) -> DeployOutcome:
        """Applies *operation* to the rule *rule_id* on the tenant, sending
        *body* (a deploy plan's payload for this tenant) as its bytes. Returns
        the platform's identifier of the rule.

        A whole deploy run (the plan, the deployment state, the retirements) is
        ``Workspace.run_json(["deploy", ...])``; this deploys one compiled rule.

        Raises :class:`OpentideError`: ``tenant_refused``, the other codes of
        :meth:`query`, and ``operation_unsupported`` on a platform whose rules
        deploy only through ``opentide deploy`` (Elastic).
        """
        data = await _document(self._inner.deploy, rule_id, operation, bytes(body))
        return DeployOutcome(**data)

    def __repr__(self) -> str:
        return f"Connection({self.platform!r}, {self.tenant!r})"


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
