"""Backward-compatibility re-export shim for deployment module."""

from Engines.modules.ci import CIEnvironment
from Engines.modules.git_repo import TideRepo, modified_mdr_files, diff_calculation
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

__all__ = [
    "CIEnvironment",
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
]
