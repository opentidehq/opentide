from __future__ import annotations
import os
import sys
from tokenize import String
from dataclasses import dataclass
from typing import Literal, Optional, List, Sequence, Mapping, Any, Union
from opentide.core.typing import Never
from enum import Enum, auto
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
import structlog
logger = structlog.get_logger('opentide.models.system_models')

@dataclass
class SystemConfig:

    @dataclass
    class Platform:
        enabled: bool
        identifier: str
        name: str
        subschema: str
        description: str
        flags: list[str]

    @dataclass
    class Modifiers:

        @dataclass
        class Conditions:
            status: Optional[Sequence[str]] = None
            flags: Optional[Sequence[Never] | Sequence[str]] = None
            tenants: Optional[Sequence[Never] | Sequence[str]] = None
            default: Optional[bool] = None
        conditions: Conditions
        modifications: Mapping[Any, str]
        name: Optional[str] = None
        description: Optional[str] = None

    @dataclass
    class Tenant:

        @dataclass
        class Setup:
            proxy: bool
            ssl: bool

        @dataclass
        class Parameters:
            ...
        name: str
        description: str
        deployment: Union[DeploymentStrategy, str]
        setup: Setup
        parameters: Optional[Parameters] = None

        def __post_init__(self):
            if type(self.deployment) is str:
                self.deployment = DeploymentStrategy[self.deployment]
    platform: Platform
    tenants: Optional[Sequence[Tenant]]
    modifiers: Optional[Sequence[Modifiers]] = None

@dataclass
class DeploymentBatch:
    """
    Base common dataclass used to construct tenant deployment
    per system
    """
    tenant: SystemConfig.Tenant
    rules: Sequence[DetectionRule]

class TenantDeployment:

    @dataclass
    class Splunk(DeploymentBatch):
        tenant: ConfigurationModels.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class Sentinel(DeploymentBatch):
        tenant: ConfigurationModels.Systems.Sentinel.Tenant

    @dataclass
    class CarbonBlackCloud(DeploymentBatch):
        tenant: ConfigurationModels.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class SentinelOne(DeploymentBatch):
        tenant: ConfigurationModels.Systems.SentinelOne.Tenant

    @dataclass
    class DefenderForEndpoint(DeploymentBatch):
        tenant: ConfigurationModels.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class Crowdstrike(DeploymentBatch):
        tenant: ConfigurationModels.Systems.Crowdstrike.Tenant

    @dataclass
    class HarfangLab(DeploymentBatch):
        tenant: ConfigurationModels.Systems.HarfangLab.Tenant
DeploymentBatch = DeploymentBatch
