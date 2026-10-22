"""`platforms/<id>.toml`: platform identity, modifiers, and tenants.

Each detection platform has its own tenant `setup` (and, for Defender,
`parameters`) model. They describe the file as written: a `$NAME`
placeholder is a valid value for any setup key, and is resolved when the
tenant loads, not here.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field

from opentide.models.configuration.base import (
    ConfigurationModel,
    EnvPlaceholder,
    OpenConfigurationModel,
    RunStrategyName,
)

_SECRET = " Use a $NAME placeholder; do not commit the value."


class PlatformIdentity(ConfigurationModel):
    """`[platform]`: whether the platform is enabled, and how it is named."""

    enabled: bool = Field(default=False, description="Load and deploy to this platform.")
    identifier: str | None = Field(
        default=None,
        description="Platform identifier (for example sentinel). Matches the file name stem.",
    )
    name: str | None = Field(default=None, description="Display name of the platform.")
    subschema: str | None = Field(
        default=None, description="Title of the platform's rule sub-schema."
    )
    description: str = Field(default="", description="What the platform is.")
    flags: list[str] = Field(
        default_factory=list, description="Flags a modifier condition can match."
    )


class LegacyTideIdentity(OpenConfigurationModel):
    """`[tide]`: CoreTIDE-era identity table. `identifier` keys the file."""

    identifier: str | None = Field(
        default=None, description="Platform identifier, read when [platform] has none."
    )


class ModifierConditions(ConfigurationModel):
    """`[modifiers.conditions]`: which rules a modifier applies to."""

    status: list[str] | None = Field(
        default=None, description="Apply to rules in one of these deployment statuses."
    )
    flags: list[str] | None = Field(
        default=None, description="Apply to rules carrying one of these flags."
    )
    tenants: list[str] | None = Field(
        default=None, description="Apply when deploying to one of these tenants."
    )
    default: bool | None = Field(
        default=None, description="Apply to every rule, as platform defaults."
    )


class Modifier(ConfigurationModel):
    """`[[modifiers]]`: rule values rewritten at deploy time when the conditions match."""

    name: str | None = Field(default=None, description="Modifier name.")
    description: str | None = Field(default=None, description="What the modifier is for.")
    conditions: ModifierConditions = Field(description="When the modifier applies.")
    modifications: dict[str, Any] = Field(
        description="Rule values to set, keyed by dotted platform field path."
    )


class TenantSetup(ConfigurationModel):
    """`[tenants.setup]`: connection settings shared by every platform."""

    ssl: bool | str = Field(
        default=True,
        description="Verify the tenant's TLS certificate. A $NAME placeholder is allowed.",
    )


class TenantBase(ConfigurationModel):
    """`[[tenants]]`: one deployment target of the platform."""

    name: str = Field(min_length=1, description="Tenant name a rule's platform block may list.")
    description: str = Field(default="", description="What the tenant is.")
    strategies: list[RunStrategyName] | RunStrategyName | None = Field(
        default=None,
        description="Status strategies the tenant accepts (PREVIEW, RELEASE). Omit for both.",
    )
    manual: bool = Field(
        default=False, description="Only rules whose platform block lists this tenant reach it."
    )


class PlatformConfigurationBase(ConfigurationModel):
    """Merged `platforms/<id>.toml`."""

    platform: PlatformIdentity = Field(
        default_factory=PlatformIdentity, description="Platform identity."
    )
    tide: LegacyTideIdentity | None = Field(
        default=None, description="CoreTIDE-era identity table."
    )
    modifiers: list[Modifier] = Field(
        default_factory=list, description="Deploy-time rule modifiers."
    )


# --- Sentinel -------------------------------------------------------------------------


class SentinelSetup(TenantSetup):
    """`[tenants.setup]` for Microsoft Sentinel."""

    resource_group: str = Field(description="Azure resource group of the workspace.")
    workspace_name: str = Field(description="Log Analytics workspace name.")
    workspace_id: str = Field(description="Log Analytics workspace ID.")
    azure_tenant_id: str = Field(description="Entra ID tenant ID.")
    azure_subscription_id: str = Field(description="Azure subscription ID.")
    azure_client_id: str = Field(description="App registration client ID.")
    azure_client_secret: str = Field(description="App registration client secret." + _SECRET)


class SentinelTenant(TenantBase):
    """`[[tenants]]` for Microsoft Sentinel."""

    setup: SentinelSetup = Field(description="Connection settings.")


class SentinelConfiguration(PlatformConfigurationBase):
    """Merged `platforms/sentinel.toml`."""

    tenants: list[SentinelTenant] = Field(default_factory=list, description="Sentinel tenants.")


# --- Splunk ---------------------------------------------------------------------------


class SplunkSetup(TenantSetup):
    """`[tenants.setup]` for Splunk."""

    url: str = Field(description="Splunk management URL.")
    port: int | str = Field(description="Splunk management port.")
    app: str = Field(description="Splunk app the searches are saved in.")
    token: str = Field(default="", description="Splunk authentication token." + _SECRET)
    correlation_searches: bool | EnvPlaceholder = Field(
        default=True, description="Save rules as Enterprise Security correlation searches."
    )
    allow_skew: str | None = Field(default=None, description="Splunk allow_skew value.")
    schedule_offset: int | EnvPlaceholder = Field(
        default=0, description="Minutes added to the computed schedule."
    )
    frequency_scheduling: str = Field(
        default="random", description="How a search's cron minute is chosen."
    )
    actions_enabled: list[str] | None = Field(
        default=None, description="Alert actions a rule may enable."
    )
    default_actions: list[str] | None = Field(
        default=None, description="Alert actions enabled when a rule names none."
    )
    enterprise_security: bool | EnvPlaceholder = Field(
        default=False, description="The instance runs Splunk Enterprise Security."
    )


class SplunkTenant(TenantBase):
    """`[[tenants]]` for Splunk."""

    setup: SplunkSetup = Field(description="Connection settings.")


class SplunkConfiguration(PlatformConfigurationBase):
    """Merged `platforms/splunk.toml`."""

    tenants: list[SplunkTenant] = Field(default_factory=list, description="Splunk tenants.")
    modifiers: list[Modifier] | dict[str, Any] = Field(
        default_factory=list,
        description="Deploy-time rule modifiers. A [modifiers] table is the legacy layout.",
    )
    defaults: dict[str, Any] | None = Field(
        default=None, description="Saved-search values applied to every rule."
    )
    setup: dict[str, Any] | None = Field(
        default=None, description="Legacy connection settings, read when no tenant is set."
    )
    secrets: dict[str, Any] | None = Field(
        default=None, description="Legacy secrets, read when no tenant is set."
    )


# --- Carbon Black Cloud ---------------------------------------------------------------


class CarbonBlackCloudSetup(TenantSetup):
    """`[tenants.setup]` for Carbon Black Cloud."""

    url: str = Field(description="Carbon Black Cloud API URL.")
    org_key: str = Field(description="Organisation key.")
    token: str = Field(description="API token." + _SECRET)
    watchlist: str | None = Field(default=None, description="Watchlist the rules are added to.")
    organizations: list[str] | None = Field(
        default=None, description="Organisations the watchlist applies to."
    )


class CarbonBlackCloudTenant(TenantBase):
    """`[[tenants]]` for Carbon Black Cloud."""

    setup: CarbonBlackCloudSetup = Field(description="Connection settings.")


class CarbonBlackCloudConfiguration(PlatformConfigurationBase):
    """Merged `platforms/carbon_black_cloud.toml`."""

    tenants: list[CarbonBlackCloudTenant] = Field(
        default_factory=list, description="Carbon Black Cloud tenants."
    )
    setup: dict[str, Any] | None = Field(
        default=None, description="Legacy connection settings, read when no tenant is set."
    )
    secrets: dict[str, Any] | None = Field(
        default=None, description="Legacy secrets, read when no tenant is set."
    )
    validation: dict[str, Any] | None = Field(
        default=None, description="Legacy query validation settings."
    )


# --- SentinelOne ----------------------------------------------------------------------


class SentinelOneSetup(TenantSetup):
    """`[tenants.setup]` for SentinelOne."""

    url: str = Field(description="SentinelOne console URL.")
    account_id: int | EnvPlaceholder = Field(description="Account ID the rules belong to.")
    api_token: str = Field(description="API token." + _SECRET)
    site_id: int | EnvPlaceholder | None = Field(
        default=None, description="Site ID, when the rules are scoped to one site."
    )


class SentinelOneTenant(TenantBase):
    """`[[tenants]]` for SentinelOne."""

    setup: SentinelOneSetup = Field(description="Connection settings.")


class SentinelOneConfiguration(PlatformConfigurationBase):
    """Merged `platforms/sentinel_one.toml`."""

    tenants: list[SentinelOneTenant] = Field(
        default_factory=list, description="SentinelOne tenants."
    )


# --- Defender for Endpoint ------------------------------------------------------------


class DefenderForEndpointSetup(TenantSetup):
    """`[tenants.setup]` for Microsoft Defender for Endpoint."""

    tenant_id: str = Field(description="Entra ID tenant ID.")
    client_id: str = Field(description="App registration client ID.")
    client_secret: str = Field(description="App registration client secret." + _SECRET)


class DefenderForEndpointParameters(ConfigurationModel):
    """`[tenants.parameters]` for Microsoft Defender for Endpoint."""

    device_groups: list[str] | None = Field(
        default=None, description="Device groups a rule's scope may name."
    )


class DefenderForEndpointTenant(TenantBase):
    """`[[tenants]]` for Microsoft Defender for Endpoint."""

    setup: DefenderForEndpointSetup = Field(description="Connection settings.")
    parameters: DefenderForEndpointParameters | None = Field(
        default=None, description="Values rules can select from."
    )


class DefenderForEndpointConfiguration(PlatformConfigurationBase):
    """Merged `platforms/defender_for_endpoint.toml`."""

    tenants: list[DefenderForEndpointTenant] = Field(
        default_factory=list, description="Defender for Endpoint tenants."
    )


# --- CrowdStrike ----------------------------------------------------------------------


class CrowdstrikeSetup(TenantSetup):
    """`[tenants.setup]` for CrowdStrike Falcon."""

    api: str = Field(description="Falcon API base URL.")
    client_id: str = Field(description="API client ID.")
    client_secret: str = Field(description="API client secret." + _SECRET)
    customer_id: str = Field(description="Customer ID (CID).")


class CrowdstrikeTenant(TenantBase):
    """`[[tenants]]` for CrowdStrike Falcon."""

    setup: CrowdstrikeSetup = Field(description="Connection settings.")


class CrowdstrikeConfiguration(PlatformConfigurationBase):
    """Merged `platforms/crowdstrike.toml`."""

    tenants: list[CrowdstrikeTenant] = Field(
        default_factory=list, description="CrowdStrike tenants."
    )


# --- HarfangLab -----------------------------------------------------------------------


class HarfangLabSetup(TenantSetup):
    """`[tenants.setup]` for HarfangLab."""

    type: str = Field(description="Rule type the tenant receives.")
    url: str = Field(description="HarfangLab manager URL.")
    api_token: str = Field(description="API token." + _SECRET)
    source_id: str = Field(description="Rule source the rules are written to.")


class HarfangLabTenant(TenantBase):
    """`[[tenants]]` for HarfangLab."""

    setup: HarfangLabSetup = Field(description="Connection settings.")


class HarfangLabConfiguration(PlatformConfigurationBase):
    """Merged `platforms/harfanglab.toml`."""

    tenants: list[HarfangLabTenant] = Field(default_factory=list, description="HarfangLab tenants.")


# --- Elastic --------------------------------------------------------------------------


class ElasticSetup(TenantSetup):
    """`[tenants.setup]` for Elastic Security."""

    url: str = Field(description="Kibana URL.")
    elasticsearch_url: str = Field(description="Elasticsearch URL.")
    api_key: str = Field(description="API key. Must be a $NAME placeholder.")
    space: str = Field(default="default", description="Kibana space the rules are saved in.")
    index: list[str] | None = Field(default=None, description="Index patterns rules search.")
    tags: list[str] | None = Field(default=None, description="Tags added to every rule.")
    suppression: bool | EnvPlaceholder = Field(
        default=True, description="Apply alert suppression settings."
    )


class ElasticTenant(TenantBase):
    """`[[tenants]]` for Elastic Security."""

    setup: ElasticSetup = Field(description="Connection settings.")


class ElasticConfiguration(PlatformConfigurationBase):
    """Merged `platforms/elastic.toml`."""

    tenants: list[ElasticTenant] = Field(default_factory=list, description="Elastic tenants.")


# --- Any other platform file ----------------------------------------------------------


class GenericTenantSetup(TenantSetup):
    """`[tenants.setup]` of a platform opentide has no model for."""

    model_config = ConfigDict(extra="allow")


class GenericTenant(TenantBase):
    """`[[tenants]]` of a platform opentide has no model for."""

    setup: GenericTenantSetup = Field(
        default_factory=GenericTenantSetup, description="Connection settings."
    )
    parameters: dict[str, list[str]] | None = Field(
        default=None, description="Values rules can select from."
    )


class PlatformConfiguration(PlatformConfigurationBase):
    """Merged `platforms/<id>.toml` for a platform opentide has no model for."""

    tenants: list[GenericTenant] = Field(default_factory=list, description="Tenants.")


#: Model of each platform file, keyed by platform identifier.
PLATFORM_CONFIGURATION_MODELS: dict[str, type[PlatformConfigurationBase]] = {
    "sentinel": SentinelConfiguration,
    "splunk": SplunkConfiguration,
    "carbon_black_cloud": CarbonBlackCloudConfiguration,
    "sentinel_one": SentinelOneConfiguration,
    "defender_for_endpoint": DefenderForEndpointConfiguration,
    "crowdstrike": CrowdstrikeConfiguration,
    "harfanglab": HarfangLabConfiguration,
    "elastic": ElasticConfiguration,
}


def platform_configuration_model(identifier: str) -> type[PlatformConfigurationBase]:
    """The model of `platforms/<identifier>.toml`."""
    return PLATFORM_CONFIGURATION_MODELS.get(identifier, PlatformConfiguration)
