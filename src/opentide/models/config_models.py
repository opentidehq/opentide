from collections.abc import Sequence
from dataclasses import dataclass

# TODO - Re-Architect Uber Class by merging this and OpenTide
# OpenTide.Models. #DataModels
# OpenTide.Objects. #Returning Models
# OpenTide.Configurations.
# OpenTide.Deployment. #Returns Initialized deployment classes
# OpenTide.Vocabularies.
# OpenTide.Schemas.Json / OpenTide.Schemas.Yaml
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.system_models import SystemConfig


@dataclass
class ConfigurationModels:
    @dataclass
    class Deployment:
        @dataclass
        class Status:
            name: str
            description: str
            strategy: StatusStrategy | str

            def __post_init__(self):
                if type(self.strategy) is str:
                    self.strategy = StatusStrategy[self.strategy]

        statuses = Sequence[Status]

    @dataclass
    class Systems:
        @dataclass
        class Sentinel(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    resource_group: str
                    workspace_name: str
                    workspace_id: str
                    azure_tenant_id: str
                    azure_subscription_id: str
                    azure_client_id: str
                    azure_client_secret: str

                setup: Setup

        @dataclass
        class Splunk(SystemConfig): ...

        @dataclass
        class CarbonBlackCloud(SystemConfig): ...

        @dataclass
        class SentinelOne(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    url: str
                    account_id: int
                    api_token: str
                    site_id: int | None = None

                setup: Setup

        @dataclass
        class DefenderForEndpoint(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Parameters:
                    device_groups: Sequence[str] | None = None

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    tenant_id: str
                    client_id: str
                    client_secret: str

                setup: Setup
                parameters: Parameters | None = None

            tenants: Sequence[Tenant] | None

        @dataclass
        class Crowdstrike(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    api: str
                    client_id: str
                    client_secret: str
                    customer_id: str

                setup: Setup

            tenants: Sequence[Tenant] | None

        @dataclass
        class HarfangLab(SystemConfig):
            @dataclass
            class Platform(SystemConfig.Platform):
                pass

            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    type: str  # "Sigma" or "YARA"
                    url: str
                    api_token: str
                    source_id: str

                setup: Setup

            tenants: Sequence[Tenant] | None


# Legacy alias
ConfigurationModels = ConfigurationModels

# Legacy alias
ConfigurationModels = ConfigurationModels
