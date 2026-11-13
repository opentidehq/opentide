"""opentide: spec-driven development for agentic detection engineering.

The SDK is :class:`opentide.Workspace` (``open``, ``validate``, ``lint``,
``rules``, ``catalog``, ``deploy_plan``, ``tenants``, ...),
:func:`opentide.run_json` and :class:`opentide.Connection` (a tenant's async
``query``, ``validate_query`` and ``deploy``), the ``opentide`` Rust crate bound
one to one (UC-5.2). The Tide models are :mod:`opentide.models`, the platform
plugin API :mod:`opentide.plugins`; the ``opentide`` command line is the same
Rust core, run in process (:mod:`opentide._cli`).
"""

from __future__ import annotations

from opentide._version import __version__

#: ``typing.TYPE_CHECKING`` without importing typing, which the console
#: script's start would pay for (UC-3.8b, #960); type checkers read it as True.
TYPE_CHECKING = False

if TYPE_CHECKING:
    from opentide.sdk import (
        Canceller,
        Capabilities,
        Connection,
        DeployOutcome,
        DeployPlan,
        LintReport,
        LiveCheck,
        OpentideError,
        QueryResult,
        TenantConfig,
        Validation,
        Workspace,
        run_json,
    )

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
    "__version__",
    "run_json",
]

#: The SDK's names, from ``opentide.sdk``, loaded on first use.
_SDK = frozenset(
    {
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
        "run_json",
    }
)


def __getattr__(name: str) -> object:
    """Resolve the SDK on first use.

    Lazy so that ``import opentide`` (which every ``opentide.*`` import runs)
    does not load the engine.
    """
    if name in _SDK:
        from opentide import sdk

        return getattr(sdk, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
