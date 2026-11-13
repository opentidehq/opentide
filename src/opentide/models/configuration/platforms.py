"""`platforms/<id>.toml`: platform identity, modifiers, and tenants.

Each detection platform has its own tenant `setup` (and, for Defender,
`parameters`) model. They describe the file as written: a `$NAME`
placeholder is a valid value for any setup key, and is resolved when the
tenant loads, not here.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, model_validator

from opentide.models.configuration.base import (
    ConfigurationModel,
    EnvPlaceholder,
    RunStrategyName,
    SslValue,
)

_SECRET = " Use a $NAME placeholder; do not commit the value."


class PlatformIdentity(ConfigurationModel):
    """`[platform]`: whether the platform is enabled, and how it is named.

    The file name stem (`platforms/splunk.toml`) identifies the platform.
    """

    enabled: bool = Field(default=False, description="Load and deploy to this platform.")
    name: str | None = Field(default=None, description="Display name of the platform.")
    description: str = Field(default="", description="What the platform is.")


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

    ssl: SslValue = Field(
        default=True,
        description=(
            "Verify the tenant's TLS certificate: a boolean, true/false, yes/no, on/off, "
            "1/0, or a $NAME placeholder."
        ),
    )


class TenantBase(ConfigurationModel):
    """`[[tenants]]`: one deployment target of the platform."""

    name: str = Field(min_length=1, description="Tenant name a rule's platform block may list.")
    description: str = Field(default="", description="What the tenant is.")
    strategies: Annotated[list[RunStrategyName], Field(min_length=1)] | RunStrategyName | None = (
        Field(
            default=None,
            description="Status strategies the tenant accepts (PREVIEW, RELEASE). Omit for both.",
        )
    )
    manual: bool = Field(
        default=False, description="Only rules whose platform block lists this tenant reach it."
    )


class PlatformConfigurationBase(ConfigurationModel):
    """Merged `platforms/<id>.toml`."""

    platform: PlatformIdentity = Field(
        default_factory=PlatformIdentity, description="Platform identity."
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
    allow_skew: str | int | float | None = Field(
        default=None, description="Splunk allow_skew value."
    )
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


# --- SentinelOne ----------------------------------------------------------------------


class SentinelOneSetup(TenantSetup):
    """`[tenants.setup]` for SentinelOne."""

    url: str = Field(description="SentinelOne console URL.")
    account_id: int | str = Field(
        description=(
            "Account ID the rules belong to: a number, a quoted ID or a $NAME placeholder."
        )
    )
    api_token: str = Field(description="API token." + _SECRET)
    site_id: int | str | None = Field(
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
    api_key: EnvPlaceholder = Field(description="API key. Must be a $NAME placeholder.")
    space: str = Field(default="default", description="Kibana space the rules are saved in.")
    index: list[str] | None = Field(default=None, description="Index patterns rules search.")
    tags: list[str] | None = Field(default=None, description="Tags added to every rule.")
    suppression: bool | EnvPlaceholder = Field(
        default=True, description="Apply alert suppression settings."
    )
    version: str | None = Field(
        default=None,
        pattern=r"^(?:[0-9]+\.[0-9]+|serverless)$",
        description=(
            "Stack version the tenant runs, MAJOR.MINOR (8.19, 9.5) or serverless. "
            "Editors check ES|QL against the lowest version a rule targets; "
            "unset means the 8.19 floor."
        ),
    )


class ElasticTenant(TenantBase):
    """`[[tenants]]` for Elastic Security."""

    setup: ElasticSetup = Field(description="Connection settings.")


class ElasticConfiguration(PlatformConfigurationBase):
    """Merged `platforms/elastic.toml`."""

    tenants: list[ElasticTenant] = Field(default_factory=list, description="Elastic tenants.")


# --- Sysdig Secure --------------------------------------------------------------------


class SysdigSetup(TenantSetup):
    """`[tenants.setup]` for Sysdig Secure."""

    url: str = Field(description="Sysdig Secure base URL for the account's region.")
    api_token: EnvPlaceholder = Field(
        description="Sysdig Secure API token. Must be a $NAME placeholder."
    )
    policies: list[str] = Field(
        default_factory=list,
        description="Runtime policies every new rule joins when its block names none.",
    )
    tags: list[str] | None = Field(default=None, description="Tags added to every rule.")


class SysdigTenant(TenantBase):
    """`[[tenants]]` for Sysdig Secure."""

    setup: SysdigSetup = Field(description="Connection settings.")


class SysdigConfiguration(PlatformConfigurationBase):
    """Merged `platforms/sysdig.toml`."""

    tenants: list[SysdigTenant] = Field(default_factory=list, description="Sysdig tenants.")


# --- Bitdefender GravityZone ----------------------------------------------------------

#: A GravityZone object id: 24 lower-case hex digits.
GravityZoneId = Annotated[str, Field(pattern=r"^[0-9a-f]{24}$")]


class BitdefenderEndpointTag(ConfigurationModel):
    """An `endpoint_tags` entry: the GravityZone tag and the company that owns it."""

    tag_id: GravityZoneId = Field(description="GravityZone tag id, 24 hex.")
    company_id: GravityZoneId = Field(description="Company id of the tag, 24 hex.")


#: An alias in a `targets` list: a non-blank name from the tenant's tables.
TargetAlias = Annotated[str, Field(pattern=r"\S")]


class BitdefenderTenantTargets(ConfigurationModel):
    """`[tenants.setup.targets]`: default targets for blocks that set none.

    The same shape as a block's `targets` (`bitdefender_targets_shape`): exactly
    one of the two lists, non-empty. A default never means "no targets": a tenant
    that applies rules to the whole company leaves `targets` out.
    """

    endpoint_tags: Annotated[list[TargetAlias], Field(min_length=1)] | None = Field(
        default=None, description="Aliases from the tenant's endpoint_tags table."
    )
    companies: Annotated[list[TargetAlias], Field(min_length=1)] | None = Field(
        default=None, description="Aliases from the tenant's companies table."
    )

    @model_validator(mode="after")
    def _exactly_one_list(self) -> BitdefenderTenantTargets:
        if (self.endpoint_tags is None) == (self.companies is None):
            raise ValueError(
                "targets sets exactly one of endpoint_tags and companies "
                "(bitdefender_targets_shape); leave targets out for the whole company"
            )
        return self


class BitdefenderSetup(TenantSetup):
    """`[tenants.setup]` for Bitdefender GravityZone."""

    url: str = Field(
        description="Control Center API Access URL, ending in /api. Calls go to "
        "<url>/v1.0/jsonrpc/incidents."
    )
    api_key: EnvPlaceholder = Field(
        description="GravityZone API key with the Incidents API. Must be a $NAME placeholder."
    )
    key_type: Literal["personal", "service"] = Field(
        default="personal",
        description="personal: HTTP Basic with the key as user name; service: X-API-Key header.",
    )
    company_id: GravityZoneId | None = Field(
        default=None, description="Partner tenants: the company that owns created rules."
    )
    automatic_actions: bool = Field(
        default=True, description="false for subscriptions without automatic actions."
    )
    targets: BitdefenderTenantTargets | None = Field(
        default=None, description="Default targets for blocks that set none."
    )
    endpoint_tags: dict[str, BitdefenderEndpointTag] = Field(
        default_factory=dict, description="Alias to {tag_id, company_id}."
    )
    companies: dict[str, GravityZoneId] = Field(
        default_factory=dict, description="Alias to company id."
    )
    tags: list[str] = Field(default_factory=list, description="Tags added to every rule.")


class BitdefenderTenant(TenantBase):
    """`[[tenants]]` for Bitdefender GravityZone."""

    setup: BitdefenderSetup = Field(description="Connection settings.")


class BitdefenderConfiguration(PlatformConfigurationBase):
    """Merged `platforms/bitdefender.toml`."""

    tenants: list[BitdefenderTenant] = Field(
        default_factory=list, description="GravityZone tenants."
    )


# --- Graylog --------------------------------------------------------------------------

#: A Graylog object id: 24 lower-case hex digits.
GraylogId = Annotated[str, Field(pattern=r"^[0-9a-f]{24}$")]
#: A non-blank alias or tag.
GraylogName = Annotated[str, Field(pattern=r"\S")]


class GraylogSetup(TenantSetup):
    """`[tenants.setup]` for Graylog."""

    url: str = Field(description="The Graylog web interface's base URL. Calls go to <url>/api/....")
    token: EnvPlaceholder = Field(
        description="A Graylog access token, sent as HTTP Basic <token>:token. Must be a $NAME "
        "placeholder."
    )
    allow_leading_wildcard: bool = Field(
        default=False, description="Mirrors the server's allow_leading_wildcard_searches."
    )
    streams: GraylogName | list[GraylogName] = Field(
        default_factory=list, description="Default stream aliases for blocks that set no streams."
    )
    stream_ids: dict[str, GraylogId] = Field(
        default_factory=dict, description="Alias to stream id, 24 hex."
    )
    notification_ids: dict[str, GraylogId] = Field(
        default_factory=dict, description="Alias to notification id, 24 hex."
    )
    tags: GraylogName | list[GraylogName] = Field(
        default_factory=list, description="Tags added to every definition on this tenant (7.2+)."
    )


class GraylogTenant(TenantBase):
    """`[[tenants]]` for Graylog."""

    setup: GraylogSetup = Field(description="Connection settings.")


class GraylogConfiguration(PlatformConfigurationBase):
    """Merged `platforms/graylog.toml`."""

    tenants: list[GraylogTenant] = Field(default_factory=list, description="Graylog tenants.")


# --- Exabeam New-Scale SIEM -----------------------------------------------------------


class ExabeamSetup(TenantSetup):
    """`[tenants.setup]` for Exabeam New-Scale SIEM."""

    region: Literal["us-west", "us-east", "ca", "eu", "sa", "sg", "ch", "jp", "au", "uk"] = Field(
        description="Exabeam API region. Calls go to https://api.<region>.exabeam.cloud; it is "
        "not derived from the console URL (use1 is us-east, euw6 is ch)."
    )
    client_id: EnvPlaceholder = Field(
        description="API key with Correlation Rules at Read Write Delete. Must be a $NAME "
        "placeholder."
    )
    client_secret: EnvPlaceholder = Field(
        description="API key secret. Must be a $NAME placeholder."
    )
    api_url: str | None = Field(
        default=None,
        pattern=r"^https://",
        description="An HTTPS base URL that replaces the region's.",
    )
    test_mode: bool = Field(
        default=False, description="Default test_mode for blocks that do not set it."
    )


class ExabeamTenant(TenantBase):
    """`[[tenants]]` for Exabeam New-Scale SIEM."""

    setup: ExabeamSetup = Field(description="Connection settings.")


class ExabeamConfiguration(PlatformConfigurationBase):
    """Merged `platforms/exabeam.toml`."""

    tenants: list[ExabeamTenant] = Field(default_factory=list, description="Exabeam tenants.")


# --- Google Security Operations -------------------------------------------------------


class GoogleSecopsSetup(TenantSetup):
    """`[tenants.setup]` for Google Security Operations."""

    project: str = Field(
        min_length=1,
        description="The Google Cloud project bound to the SecOps instance, id or number.",
    )
    location: str = Field(
        min_length=1,
        description=(
            "The instance's region: us, eu, europe, or a Google Cloud region such as europe-west2."
        ),
    )
    instance: str = Field(min_length=1, description="The SecOps customer id (a UUID).")
    endpoint: str | None = Field(
        default=None,
        description="The regional service endpoint. Default: https://<location>-chronicle.googleapis.com.",
    )
    credentials: EnvPlaceholder | None = Field(
        default=None,
        description=(
            "A $NAME placeholder for a service-account key, as a JSON document or a path to "
            "one. Without it, Application Default Credentials (workload identity, gcloud auth)."
        ),
    )
    data_access_scope: str | None = Field(
        default=None,
        description="A data access scope id, sent as scope on create and update.",
    )
    deletion: Literal["archive", "delete"] = Field(
        default="archive",
        description=(
            "DELETION: archive the rule (keeps its detections and the binding), or delete it "
            "without force."
        ),
    )


class GoogleSecopsTenant(TenantBase):
    """`[[tenants]]` for Google Security Operations."""

    setup: GoogleSecopsSetup = Field(description="Connection settings.")


class GoogleSecopsConfiguration(PlatformConfigurationBase):
    """Merged `platforms/google_secops.toml`."""

    tenants: list[GoogleSecopsTenant] = Field(
        default_factory=list, description="Google SecOps instances."
    )


# --- Any other platform file ----------------------------------------------------------


class GenericTenantSetup(TenantSetup):
    """`[tenants.setup]` of a platform opentide has no model for."""

    model_config = ConfigDict(extra="allow")


class GenericTenant(TenantBase):
    """`[[tenants]]` of a platform opentide has no model for. Plugins define its keys."""

    model_config = ConfigDict(extra="allow")

    setup: GenericTenantSetup = Field(
        default_factory=GenericTenantSetup, description="Connection settings."
    )
    parameters: dict[str, Any] | None = Field(
        default=None, description="Values rules can select from."
    )


class PlatformConfiguration(PlatformConfigurationBase):
    """Merged `platforms/<id>.toml` for a platform opentide has no model for.

    A platform plugin owns its file, so tables beyond the shared ones are open.
    """

    model_config = ConfigDict(extra="allow")

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
    "sysdig": SysdigConfiguration,
    "bitdefender": BitdefenderConfiguration,
    "graylog": GraylogConfiguration,
    "exabeam": ExabeamConfiguration,
    "google_secops": GoogleSecopsConfiguration,
}
