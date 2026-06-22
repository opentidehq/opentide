from __future__ import annotations

import os
import sys
from tokenize import String
import git

from dataclasses import dataclass
from typing import Literal, Never, Optional, List, Sequence, Mapping, Any, Union
from enum import Enum, auto

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log

# TODO - Re-Architect Uber Class by merging this and OpenTide

# OpenTide.Models. #DataModels
# OpenTide.Objects. #Returning Models
# OpenTide.Configurations.
# OpenTide.Deployment. #Returns Initialized deployment classes
# OpenTide.Vocabularies.
# OpenTide.Schemas.Json / OpenTide.Schemas.Yaml

from Engines.modules.enums import DeploymentStrategy
from Engines.modules.object_models import TideModels

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
    rules: Sequence[TideModels.DetectionRule]

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


# Legacy alias
DeploymentBatch = DeploymentBatch
