"""Backward-compatibility re-export shim for deployment module."""

from Engines.modules.ci import CIEnvironment
from Engines.modules.git_repo import GitRepository, modified_mdr_files, diff_calculation
TideRepo = GitRepository  # legacy

from Engines.modules.deployment_utils import (
    SYSTEMS_CONFIGS_INDEX,
    DEPRECATED_STATUSES,
    check_status,
    make_deploy_plan,
    enabled_systems,
    Proxy,
    ExternalIdHelper,
)
from Engines.modules.deployment_planning import TideDeployment
from Engines.modules.enums import DeploymentStrategy, DetectionPlatforms

DetectionSystems = DetectionPlatforms  # legacy

__all__ = [
    "CIEnvironment",
    "GitRepository",
    "TideRepo",
    "modified_mdr_files",
    "diff_calculation",
    "SYSTEMS_CONFIGS_INDEX",
    "DEPRECATED_STATUSES",
    "check_status",
    "make_deploy_plan",
    "enabled_systems",
    "Proxy",
    "ExternalIdHelper",
    "TideDeployment",
    "DeploymentStrategy",
    "DetectionPlatforms",
    "DetectionSystems",
]
