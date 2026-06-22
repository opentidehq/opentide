"""Per-platform configuration Pydantic models — schema ``platform::<name>::1.0``."""

from __future__ import annotations

from typing import Any, ClassVar

from opentide.models.base import TideModel


class PlatformConfigBase(TideModel):
    """Shared platform block on detection rules."""

    enabled: bool = False
    name: str = ""


class SentinelConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::sentinel::1.0"

    query: str | None = None
    queryFrequency: str | None = None
    queryPeriod: str | None = None
    severity: str | None = None
    tactics: list[str] | None = None
    techniques: list[str] | None = None
    entityMappings: list[dict[str, Any]] | None = None
    customDetails: dict[str, Any] | None = None


class DefenderConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::defender_for_endpoint::1.0"

    query: str | None = None
    severity: str | None = None


class SplunkConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::splunk::1.0"

    search: str | None = None
    cron_schedule: str | None = None


class SentinelOneConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::sentinel_one::1.0"

    query: str | None = None


class CrowdstrikeConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::crowdstrike::1.0"

    query: str | None = None


class HarfangLabConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::harfanglab::1.0"

    query: str | None = None


class CarbonBlackConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::carbon_black_cloud::1.0"

    query: str | None = None


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
    model = PLATFORM_CONFIG_MODELS.get(platform)
    if model is None:
        raise ValueError(f"Unknown platform {platform!r}")
    return model.model_validate(payload)


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
        return cls.model_validate(kwargs)
