"""Backward-compatibility re-export shim for deployment module."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentide._models.deployment_enums import DetectionPlatforms, StatusStrategy
from opentide.deployment.ci import CIEnvironment
from opentide.deployment.git_repo import GitRepository, diff_calculation, modified_mdr_files
from opentide.deployment.utils import (
    DEPRECATED_STATUSES,
    Proxy,
    check_status,
    enabled_systems,
    make_deploy_plan,
)

if TYPE_CHECKING:
    from opentide.deployment.planning import TideDeployment


__all__ = [
    "DEPRECATED_STATUSES",
    "SYSTEMS_CONFIGS_INDEX",
    "CIEnvironment",
    "DetectionPlatforms",
    "GitRepository",
    "Proxy",
    "StatusStrategy",
    "TideDeployment",
    "check_status",
    "diff_calculation",
    "enabled_systems",
    "make_deploy_plan",
    "modified_mdr_files",
]


def __getattr__(name: str) -> Any:
    """Load the planning and registry-backed exports only when requested."""
    if name == "TideDeployment":
        from opentide.deployment.planning import TideDeployment

        globals()[name] = TideDeployment
        return TideDeployment
    if name == "SYSTEMS_CONFIGS_INDEX":
        # Deliberately NOT cached in globals(): it is a live view of registry
        # configuration, and importing this package must not build the index
        # (#536). Resolved from utils, which owns the name.
        from opentide.deployment import utils

        return utils.SYSTEMS_CONFIGS_INDEX
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
