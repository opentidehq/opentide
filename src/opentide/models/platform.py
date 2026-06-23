"""Per-platform configuration Pydantic models — schema ``platform::<name>::1.0``."""

from __future__ import annotations
from typing import Any, ClassVar, Literal, cast
from pydantic import Field
from opentide.models.base import TideModel
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
)


class PlatformConfigBase(TideModel):
    """Shared platform block on detection rules."""

    enabled: bool = False
    name: str = ""
    platform_schema: str | None = Field(default=None, alias="schema")
    status: str | None = None
    flags: list[str] | None = None
    tenants: list[str] | None = None
    contributors: list[str] | None = None


class SentinelConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::sentinel::1.0"
    query: str
    scheduling: SentinelScheduling
    alert: SentinelAlert
    exclusions: list[SentinelExclusion] | None = None
    template: SentinelTemplate | None = None
    trigger: SentinelTrigger | None = None
    grouping: SentinelGrouping | None = None
    entities: list[SentinelEntityMapping] | None = None


class DefenderConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::defender_for_endpoint::1.0"
    query: str
    alert: DefenderAlert
    impacted_entities: DefenderImpactedEntities
    scheduling: Literal["NRT", "1H", "3H", "12H", "24H"]
    rule_id: dict[str, int] | None = None
    actions: DefenderResponseActions | None = None
    scope: DefenderGroupScoping | None = None
    exclusions: list[DefenderExclusion] | None = None


class SplunkConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::splunk::1.0"
    search: str | None = None
    cron_schedule: str | None = None


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
    query: str
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
