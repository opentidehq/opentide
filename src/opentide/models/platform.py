"""Per-platform configuration Pydantic models — schema ``platform::<name>::1.0``."""

from __future__ import annotations

from typing import Annotated, Any, ClassVar, Literal, cast

from pydantic import AfterValidator, model_validator

from opentide.models.base import TideField, TideModel
from opentide.models.platform_configs import (
    CrowdstrikeDetails,
    CrowdstrikeSchedule,
    DefenderAlert,
    DefenderExclusion,
    DefenderGroupScoping,
    DefenderImpactedEntities,
    DefenderResponseActions,
    HarfangLabSigma,
    HarfangLabYara,
    SentinelAlert,
    SentinelEntityMapping,
    SentinelExclusion,
    SentinelGrouping,
    SentinelOneCondition,
    SentinelOneDetails,
    SentinelOneResponse,
    SentinelScheduling,
    SentinelTemplate,
    SentinelTrigger,
    SplunkActions,
    SplunkScheduling,
    SplunkTrigger,
)
from opentide.models.splunk_legacy import normalize_splunk_v2


def _query_not_blank(value: str) -> str:
    # Every deployer treats a falsy query as "nothing to deploy" and moves on,
    # so `query: ""` is the same silent skip as no query at all.
    if not value.strip():
        raise ValueError("query must not be empty")
    return value


QueryText = Annotated[str, AfterValidator(_query_not_blank)]


class PlatformConfigBase(TideModel):
    """Shared platform block on detection rules."""

    enabled: bool = False
    name: str = ""
    platform_schema: str | None = TideField(
        None,
        alias="schema",
        schema_extra={"tide.template.required": True},
    )
    status: str | None = None
    flags: list[str] | None = None
    tenants: list[str] | None = None
    contributors: list[str] | None = None


class SentinelConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::sentinel::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    scheduling: SentinelScheduling
    alert: SentinelAlert
    exclusions: list[SentinelExclusion] | None = None
    template: SentinelTemplate | None = None
    trigger: SentinelTrigger | None = None
    grouping: SentinelGrouping | None = None
    entities: list[SentinelEntityMapping] | None = None


class DefenderConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::defender_for_endpoint::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    alert: DefenderAlert
    impacted_entities: DefenderImpactedEntities
    scheduling: Literal["NRT", "1H", "3H", "12H", "24H"]
    rule_id: dict[str, int] | None = None
    actions: DefenderResponseActions | None = None
    scope: DefenderGroupScoping | None = None
    exclusions: list[DefenderExclusion] | None = None


class SplunkConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::splunk::1.0"
    # Required, like every other platform's query and like the JSON Schema
    # extras already said. Optional here meant the FieldInfo template renderer
    # emitted `#query: |` commented out for Splunk alone, and the deployer
    # silently skipped rules whose query never loaded (#233). A splunk::2.x
    # `search` is copied here by `_accept_legacy_v2_spellings` below.
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    scheduling: SplunkScheduling | None = None
    trigger: SplunkTrigger | None = None
    actions: SplunkActions | None = None
    correlation_search: bool | None = None
    advanced: dict[str, Any] | None = TideField(None, schema_extra={"tide.template.hide": True})
    # Legacy flat v2.x fields retained for backward-compatible loading
    search: str | None = TideField(None, schema_extra={"tide.template.hide": True})
    cron_schedule: str | None = TideField(None, schema_extra={"tide.template.hide": True})

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_v2_spellings(cls, data: Any) -> Any:
        """Map the splunk::2.x layout onto v3 before field validation.

        Schema validation calls ``model_validate`` on the raw YAML and never
        goes through ``load_splunk_config``, so the mapping has to live here as
        well as in the loader — and be the same function, or the two paths
        accept different rules (#233).
        """
        if not isinstance(data, dict):
            return data
        return normalize_splunk_v2(data)


class SentinelOneConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::sentinel_one::1.0"
    condition: SentinelOneCondition
    response: SentinelOneResponse | None = None
    details: SentinelOneDetails | None = None
    rule_id_bundle: dict[str, int] | None = None


class CrowdstrikeConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::crowdstrike::1.0"
    details: CrowdstrikeDetails
    schedule: CrowdstrikeSchedule
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    rule_id_bundle: dict[str, str] | None = None


class HarfangLabConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::harfanglab::1.0"
    maturity: str = "Experimental"
    confidence: str = "Moderate"
    action: str = "Alert"
    tags: list[str] | None = None
    sigma: HarfangLabSigma | None = None
    yara: HarfangLabYara | None = None
    rule_id_bundle: dict[str, str] | None = None


class CarbonBlackConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::carbon_black_cloud::1.0"
    query: QueryText = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    organizations: list[str] | None = None
    watchlist: str | None = None
    report: str | None = None
    tags: list[str] | None = None
    rule_id_bundle: dict[str, str] | None = None


PLATFORM_CONFIG_MODELS: dict[str, type[PlatformConfigBase]] = {
    "sentinel": SentinelConfig,
    "defender_for_endpoint": DefenderConfig,
    "splunk": SplunkConfig,
    "sentinel_one": SentinelOneConfig,
    "crowdstrike": CrowdstrikeConfig,
    "harfanglab": HarfangLabConfig,
    "carbon_black_cloud": CarbonBlackConfig,
}


def parse_platform_config(platform: str, payload: dict[str, Any]) -> PlatformConfigBase:
    """Validate a platform configuration block from rule YAML."""
    from opentide.loading.platform_loader import load_platform_config

    return load_platform_config(platform, payload)


class RuleConfigurations(TideModel):
    """Dynamically composed rule platform configurations."""

    sentinel: SentinelConfig | None = None
    defender_for_endpoint: DefenderConfig | None = None
    splunk: SplunkConfig | None = None
    sentinel_one: SentinelOneConfig | None = None
    crowdstrike: CrowdstrikeConfig | None = None
    harfanglab: HarfangLabConfig | None = None
    carbon_black_cloud: CarbonBlackConfig | None = None

    @classmethod
    def from_platforms_dict(cls, platforms: dict[str, dict[str, Any]]) -> RuleConfigurations:
        kwargs: dict[str, Any] = {}
        for key, value in platforms.items():
            if key in PLATFORM_CONFIG_MODELS and value:
                kwargs[key] = parse_platform_config(key, value)
        return cast(RuleConfigurations, cls.model_validate(kwargs))
