"""Backward-compatibility re-export shim for deployment module."""

from opentide.deployment.ci import CIEnvironment
from opentide.deployment.git_repo import GitRepository, diff_calculation, modified_mdr_files

TideRepo = GitRepository
from opentide.deployment.planning import TideDeployment
from opentide.deployment.utils import (
    DEPRECATED_STATUSES,
    SYSTEMS_CONFIGS_INDEX,
    ExternalIdHelper,
    Proxy,
    check_status,
    enabled_systems,
    make_deploy_plan,
)
from opentide.models.deployment_enums import DeploymentStrategy, DetectionPlatforms

DetectionSystems = DetectionPlatforms
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
