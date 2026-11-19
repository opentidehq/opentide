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

#: The package's version, from its installed metadata (the Cargo workspace's
#: version, which maturin writes into the wheel), read on first use.
__version__: str

#: ``typing.TYPE_CHECKING`` without importing typing, which the console
#: script's start would pay for (UC-3.8b, #960); type checkers read it as True.
TYPE_CHECKING = False

if TYPE_CHECKING:
    from opentide.sdk import (
        Canceller,
        Capabilities,
        Connection,
        DeployEvent,
        DeployOutcome,
        DeployPlan,
        DeployWarning,
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
    "DeployEvent",
    "DeployOutcome",
    "DeployPlan",
    "DeployWarning",
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
        "DeployEvent",
        "DeployOutcome",
        "DeployPlan",
        "DeployWarning",
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
    """Resolve the SDK and ``__version__`` on first use.

    Lazy so that ``import opentide`` (which every ``opentide.*`` import runs)
    loads neither the engine nor ``importlib.metadata``.
    """
    if name in _SDK:
        from opentide import sdk

        return getattr(sdk, name)
    if name == "__version__":
        from importlib.metadata import version

        return version(__name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


#: Module-level names that are not the package's: the `TYPE_CHECKING` flag
#: above and the `annotations` feature of `from __future__ import annotations`.
_NOT_PUBLIC = frozenset({"TYPE_CHECKING", "annotations"})


def __dir__() -> list[str]:
    return sorted((set(globals()) - _NOT_PUBLIC) | set(__all__))
