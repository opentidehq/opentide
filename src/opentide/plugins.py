"""Platform plugins: detection platforms a Python package adds to opentide.

A plugin is a :class:`PlatformPlugin` registered in the ``opentide.platforms``
entry-point group under the platform's identifier (``acme``)::

    [project.entry-points."opentide.platforms"]
    acme = "acme_opentide:AcmePlatform"

The Rust core (the command line compiled into ``opentide._native``) discovers
the entry points through this module and calls each plugin through PyO3,
behind the same traits as the built-in platforms: ``deploy`` (``Deployer``),
``validate_query`` (``LiveValidator``), ``run_query`` (``QueryRunner``) and
``check_configuration``, which ``opentide validate`` runs on each rule's
``configurations.<platform>`` block. A plugin implements the methods it
supports; the others stay :class:`PlatformPlugin`'s, and the platform does not
offer them.

Plugins load only when opentide runs from its Python package: the native
binary and the npm package cannot import Python, and say so when a workspace
enables a platform that is not built in.

The leading-underscore functions are the binding's side of the boundary
(``bindings/python/src/plugins.rs``): every value crosses as JSON text, so no
Python object outlives a call. Documentation: ``docs/sdk/platforms.md``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Literal

if TYPE_CHECKING:
    from pydantic import BaseModel

__all__ = [
    "BUILTIN_PLATFORMS",
    "ENTRY_POINT_GROUP",
    "Column",
    "ConfigurationFinding",
    "DeployRequest",
    "DeployResult",
    "LiveCheck",
    "PlatformAuthenticationError",
    "PlatformPlugin",
    "PlatformRefused",
    "QueryRequest",
    "QueryResult",
    "Tenant",
]

#: The entry-point group plugins register in.
ENTRY_POINT_GROUP = "opentide.platforms"

#: The built-in platforms: their entry points are opentide's own, and a
#: plugin cannot take one of these names.
BUILTIN_PLATFORMS = frozenset(
    {
        "sentinel",
        "defender_for_endpoint",
        "splunk",
        "sentinel_one",
        "crowdstrike",
        "harfanglab",
        "carbon_black_cloud",
        "elastic",
        "sysdig",
    }
)

#: What a platform identifier looks like: the key of its block under a
#: rule's ``configurations`` and the name of ``platforms/<id>.toml``.
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")

Operation = Literal["create", "update", "disable", "delete"]


@dataclass(frozen=True)
class Tenant:
    """One tenant of the platform, from ``platforms/<id>.toml``'s ``[[tenants]]``.

    ``setup`` holds its ``setup`` table with every ``$NAME`` resolved from
    the environment; ``lists`` its lists of strings, as written. Never log or
    repeat a setup value: it may be a secret.
    """

    platform: str
    name: str
    setup: Mapping[str, str | None]
    lists: Mapping[str, Sequence[str]]
    verify_tls: bool
    timeout: float


@dataclass(frozen=True)
class DeployRequest:
    """One rule to deploy on one tenant.

    ``body`` is ``{"rule": <the rule document>, "configuration": <its block
    under configurations.<platform>>}``, the tenant's ``[[modifiers]]``
    applied. ``operation`` is what deployment state and the block's status
    plan (``opentide deploy --strategy``): ``create`` for a rule the state
    holds no id for on this tenant, else ``update``, ``disable`` or
    ``delete`` of ``remote_id``, the id an earlier create returned.
    """

    rule_id: str
    operation: Operation
    body: Any
    remote_id: str | None = None


@dataclass(frozen=True)
class DeployResult:
    """What a deploy did: the platform's identifier of the rule, and the operation.

    A ``create`` must return ``remote_id``: deployment state records it, and
    the next deploy updates, disables or deletes the rule by it. A platform
    that addresses rules by the rule's UUID returns ``request.rule_id``.
    """

    remote_id: str | None = None
    operation: Operation | None = None


@dataclass(frozen=True)
class QueryRequest:
    """One query to run or check, over the window from ``start`` to ``end`` (UTC, ``Z``)."""

    text: str
    language: str
    start: str
    end: str
    limit: int
    index: Sequence[str] = ()
    data_view: str | None = None
    timeout: float = 120.0


@dataclass(frozen=True)
class Column:
    """A column of a query's rows, with the vendor's type name when it gives one."""

    name: str
    type: str | None = None


@dataclass
class QueryResult:
    """What a query returned: at most ``limit`` rows, each a dict in column order.

    Without ``columns``, the columns are the rows' keys in first-seen order.
    ``truncated`` says more rows matched than the limit let through.
    """

    rows: list[dict[str, Any]] = field(default_factory=list)
    columns: list[Column] | None = None
    truncated: bool = False
    partial: bool = False
    warnings: list[str] = field(default_factory=list)
    vendor_query_id: str | None = None
    sent: str | None = None
    language: str | None = None


@dataclass
class LiveCheck:
    """A tenant's verdict on a query it accepted.

    ``errors`` fail the query although the tenant ran it; a query the tenant
    refuses raises :class:`PlatformRefused` instead.
    """

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    result: QueryResult | None = None


@dataclass(frozen=True)
class ConfigurationFinding:
    """One problem in a rule's block for the platform, at *path* inside the block."""

    path: tuple[str | int, ...]
    message: str
    warning: bool = False


class PlatformRefused(Exception):
    """The tenant answered and refused: a query it cannot run, a rule it will not take."""

    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class PlatformAuthenticationError(Exception):
    """The tenant refused the credentials."""

    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class PlatformPlugin:
    """A detection platform added by a package. Override what the platform supports.

    ``configuration_model`` is a pydantic model of the platform's block of a
    rule's ``configurations``: :meth:`check_configuration` validates the block
    with it, and ``opentide validate`` reports each error at its position in
    the rule file. Override :meth:`check_configuration` to check it another way.
    """

    configuration_model: ClassVar[type[BaseModel] | None] = None

    def deploy(self, tenant: Tenant, request: DeployRequest) -> DeployResult:
        """Apply *request* to *tenant*."""
        raise NotImplementedError

    def validate_query(self, tenant: Tenant, request: QueryRequest) -> LiveCheck:
        """Check on *tenant* that the query runs (``validate query --live``)."""
        raise NotImplementedError

    def run_query(self, tenant: Tenant, request: QueryRequest) -> QueryResult:
        """Run the query on *tenant* (``opentide query``); save nothing there."""
        raise NotImplementedError

    def check_configuration(self, block: Mapping[str, Any]) -> list[ConfigurationFinding]:
        """The problems in *block*, a rule's ``configurations.<platform>``."""
        model = self.configuration_model
        if model is None:
            return []
        from pydantic import ValidationError

        try:
            model.model_validate(dict(block))
        except ValidationError as error:
            return [
                ConfigurationFinding(path=tuple(problem["loc"]), message=problem["msg"])
                for problem in error.errors()
            ]
        return []


def _overrides(plugin: PlatformPlugin, name: str) -> bool:
    return getattr(type(plugin), name) is not getattr(PlatformPlugin, name)


def capabilities(plugin: PlatformPlugin) -> dict[str, bool]:
    """What *plugin* supports: ``deploy``, ``validate``, ``query``, ``configuration``."""
    return {
        "deploy": _overrides(plugin, "deploy"),
        "validate": _overrides(plugin, "validate_query"),
        "query": _overrides(plugin, "run_query"),
        "configuration": plugin.configuration_model is not None
        or _overrides(plugin, "check_configuration"),
    }


def _instance(loaded: object) -> PlatformPlugin:
    """The plugin an entry point names: a :class:`PlatformPlugin` class, instance or factory."""
    if isinstance(loaded, PlatformPlugin):
        return loaded
    if isinstance(loaded, type) and issubclass(loaded, PlatformPlugin):
        return loaded()
    if callable(loaded):
        made = loaded()
        if isinstance(made, PlatformPlugin):
            return made
    raise TypeError(f"{loaded!r} is not an opentide.plugins.PlatformPlugin")


def _discover() -> list[dict[str, Any]]:
    """Every plugin entry point, loaded: its identifier and plugin or why it failed."""
    from importlib.metadata import entry_points

    found: list[dict[str, Any]] = []
    for point in entry_points(group=ENTRY_POINT_GROUP):
        if point.name in BUILTIN_PLATFORMS:
            continue
        if not _IDENTIFIER.fullmatch(point.name):
            found.append(
                {
                    "id": point.name,
                    "error": "a platform identifier is lower case letters, digits and _, "
                    "starting with a letter",
                }
            )
            continue
        try:
            plugin = _instance(point.load())
        except Exception as error:
            found.append({"id": point.name, "error": f"{type(error).__name__}: {error}"})
            continue
        found.append({"id": point.name, "plugin": plugin, "error": None, **capabilities(plugin)})
    return found


def _tenant(text: str) -> Tenant:
    data = json.loads(text)
    return Tenant(
        platform=data["platform"],
        name=data["name"],
        setup=dict(data["setup"]),
        lists={key: tuple(value) for key, value in data["lists"].items()},
        verify_tls=bool(data["verify_tls"]),
        timeout=float(data["timeout"]),
    )


def _query(text: str) -> QueryRequest:
    data = json.loads(text)
    return QueryRequest(
        text=data["text"],
        language=data["language"],
        start=data["start"],
        end=data["end"],
        limit=int(data["limit"]),
        index=tuple(data["index"]),
        data_view=data["data_view"],
        timeout=float(data["timeout"]),
    )


def _result(result: QueryResult) -> dict[str, Any]:
    if not isinstance(result, QueryResult):
        raise TypeError(f"run_query returned {type(result).__name__}, not QueryResult")
    document = asdict(result)
    if result.columns is None:
        document["columns"] = None
    return document


def _deploy(plugin: PlatformPlugin, tenant: str, request: str) -> dict[str, Any]:
    data = json.loads(request)
    body = data["body"]
    # The core sends the stored id inside the body (deploy_send.rs's
    # plugin_body); the plugin reads it as the request's own field.
    remote_id = body.pop("remote_id", None) if isinstance(body, dict) else None
    result = plugin.deploy(
        _tenant(tenant),
        DeployRequest(
            rule_id=data["rule_id"],
            operation=data["operation"],
            body=body,
            remote_id=remote_id,
        ),
    )
    if not isinstance(result, DeployResult):
        raise TypeError(f"deploy returned {type(result).__name__}, not DeployResult")
    return {"remote_id": result.remote_id, "operation": result.operation}


def _run_query(plugin: PlatformPlugin, tenant: str, request: str) -> dict[str, Any]:
    return _result(plugin.run_query(_tenant(tenant), _query(request)))


def _validate_query(plugin: PlatformPlugin, tenant: str, request: str) -> dict[str, Any]:
    check = plugin.validate_query(_tenant(tenant), _query(request))
    if not isinstance(check, LiveCheck):
        raise TypeError(f"validate_query returned {type(check).__name__}, not LiveCheck")
    return {
        "errors": list(check.errors),
        "warnings": list(check.warnings),
        "result": None if check.result is None else _result(check.result),
    }


def _check_configuration(plugin: PlatformPlugin, block: str) -> dict[str, Any]:
    findings = plugin.check_configuration(json.loads(block))
    return {
        "findings": [
            {
                "path": [str(part) for part in finding.path],
                "message": finding.message,
                "warning": finding.warning,
            }
            for finding in findings
        ]
    }


_METHODS: dict[str, Callable[..., dict[str, Any]]] = {
    "deploy": _deploy,
    "run_query": _run_query,
    "validate_query": _validate_query,
    "check_configuration": _check_configuration,
}


def _invoke(plugin: PlatformPlugin, method: str, *arguments: str) -> str:
    """Call *method* on *plugin* with JSON *arguments*; ``{"ok": ...}`` or ``{"error": ...}``."""
    try:
        value = _METHODS[method](plugin, *arguments)
    except PlatformRefused as error:
        answer: dict[str, Any] = {
            "error": {"kind": "refused", "message": error.message, "detail": error.detail}
        }
    except PlatformAuthenticationError as error:
        answer = {
            "error": {"kind": "authentication", "message": error.message, "detail": error.detail}
        }
    except Exception as error:
        answer = {"error": {"kind": "failed", "message": f"{type(error).__name__}: {error}"}}
    else:
        answer = {"ok": value}
    return json.dumps(answer, default=str)
