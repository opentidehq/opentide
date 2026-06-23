"""Backward-compatible model re-exports."""

from opentide.models.config_models import ConfigurationModels
from opentide.models.deployment_enums import DeploymentStrategy, DetectionPlatforms, StatusStrategy
from opentide.models.object_models import DetectionRule, SharedModels, ThreatVector, TideModels
from opentide.models.system_models import DeploymentBatch, SystemConfig, TenantDeployment

DetectionSystems = DetectionPlatforms
TenantDeploymentModel = DeploymentBatch
TideConfigs = ConfigurationModels
ObjectMetadata = SharedModels.ObjectMetadata
ObjectReferences = SharedModels.ObjectReferences
PlatformConfigurationBase = SharedModels.PlatformConfigurationBase
TideDefinitionsModels = SharedModels
__all__ = [
    "StatusStrategy",
    "DetectionPlatforms",
    "DetectionSystems",
    "DeploymentStrategy",
    "SystemConfig",
    "ConfigurationModels",
    "TideConfigs",
    "SharedModels",
    "TideDefinitionsModels",
    "TideModels",
    "DetectionRule",
    "ThreatVector",
    "ObjectMetadata",
    "ObjectReferences",
    "PlatformConfigurationBase",
    "DeploymentBatch",
    "TenantDeploymentModel",
    "TenantDeployment",
]
