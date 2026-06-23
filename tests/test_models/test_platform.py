"""Platform configuration models."""

from __future__ import annotations

from opentide.models.platform import (
    PLATFORM_CONFIG_MODELS,
    RuleConfigurations,
    SentinelConfig,
    parse_platform_config,
)


def test_parse_platform_config_sentinel() -> None:
    config = parse_platform_config(
        "sentinel",
        {
            "enabled": True,
            "name": "Sentinel",
            "query": "SecurityEvent | take 1",
            "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
            "alert": {"title": "T", "suppression": False},
        },
    )
    assert isinstance(config, SentinelConfig)
    assert config.enabled is True


def test_rule_configurations_from_platforms_dict() -> None:
    configs = RuleConfigurations.from_platforms_dict(
        {
            "sentinel": {
                "enabled": True,
                "name": "S",
                "query": "SecurityEvent | take 1",
                "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
                "alert": {"title": "T", "suppression": False},
            },
            "crowdstrike": {
                "enabled": False,
                "name": "C",
                "query": "index=main",
                "details": {"trigger": "event", "outcome": "detection"},
                "schedule": {"frequency": "1h", "lookback": "2h"},
            },
        }
    )
    assert configs.sentinel is not None
    assert configs.crowdstrike is not None


def test_platform_config_models_cover_seven_platforms() -> None:
    assert len(PLATFORM_CONFIG_MODELS) == 7
