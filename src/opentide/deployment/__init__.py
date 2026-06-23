"""Backward-compatibility re-export shim for deployment module."""
from opentide.deployment.ci import CIEnvironment
from opentide.deployment.git_repo import GitRepository, modified_mdr_files, diff_calculation
TideRepo = GitRepository
from opentide.deployment.utils import SYSTEMS_CONFIGS_INDEX, DEPRECATED_STATUSES, check_status, make_deploy_plan, enabled_systems, Proxy, ExternalIdHelper
from opentide.deployment.planning import TideDeployment
from opentide.models.deployment_enums import DeploymentStrategy, DetectionPlatforms
DetectionSystems = DetectionPlatforms
__all__ = ['CIEnvironment', 'GitRepository', 'TideRepo', 'modified_mdr_files', 'diff_calculation', 'SYSTEMS_CONFIGS_INDEX', 'DEPRECATED_STATUSES', 'check_status', 'make_deploy_plan', 'enabled_systems', 'Proxy', 'ExternalIdHelper', 'TideDeployment', 'DeploymentStrategy', 'DetectionPlatforms', 'DetectionSystems']
