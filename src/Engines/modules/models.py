"""Backward-compatibility re-export shim for models module."""

from Engines.modules.enums import StatusStrategy, DetectionPlatforms, DeploymentStrategy
DetectionSystems = DetectionPlatforms  # legacy

from Engines.modules.system_models import SystemConfig, DeploymentBatch, TenantDeployment
TenantDeploymentModel = DeploymentBatch  # legacy

from Engines.modules.config_models import ConfigurationModels
TideConfigs = ConfigurationModels  # legacy

from Engines.modules.object_models import (
    SharedModels,
    TideModels,
    DetectionRule,
    ThreatVector,
)
ObjectMetadata = SharedModels.ObjectMetadata
ObjectReferences = SharedModels.ObjectReferences
PlatformConfigurationBase = SharedModels.PlatformConfigurationBase
TideDefinitionsModels = SharedModels  # legacy

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
