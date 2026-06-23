"""Per-platform configuration loaders."""

from __future__ import annotations

from opentide.loading.platform_loader import (
    load_crowdstrike_config,
    load_defender_config,
    load_sentinel_config,
    load_sentinel_one_config,
)
from opentide.models.platform import SentinelConfig


def test_sentinel_config_loader_parses_alert_and_scheduling() -> None:
    config = load_sentinel_config(
        {
            "enabled": True,
            "name": "Sentinel rule",
            "schema": "platform::sentinel::1.0",
            "status": "STAGING",
            "query": "SecurityEvent | take 1",
            "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
            "alert": {
                "title": "Alert",
                "suppression": False,
                "custom_details": [{"key": "host", "column": "Computer"}],
            },
        }
    )
    assert isinstance(config, SentinelConfig)
    assert config.alert.title == "Alert"
    assert config.scheduling.frequency == "PT1H"
    assert config.alert.custom_details is not None
    assert config.alert.custom_details[0].key == "host"


def test_defender_config_loader_parses_nested_actions() -> None:
    config = load_defender_config(
        {
            "schema": "platform::defender_for_endpoint::1.0",
            "status": "STAGING",
            "query": "DeviceProcessEvents | take 1",
            "scheduling": "1H",
            "alert": {"category": "Execution"},
            "impacted_entities": {"device": "device_id"},
            "scope": {"selection": "All"},
            "actions": {
                "devices": {"run_antivirus_scan": True},
            },
        }
    )
    assert config.actions is not None
    assert config.actions.devices is not None
    assert config.actions.devices.run_antivirus_scan is True


def test_crowdstrike_config_loader_parses_rule_id_bundle() -> None:
    config = load_crowdstrike_config(
        {
            "schema": "platform::crowdstrike::1.0",
            "status": "STAGING",
            "query": "index=main",
            "details": {"trigger": "event", "outcome": "detection"},
            "schedule": {"frequency": "1h", "lookback": "2h"},
            "rule_id::tenant-a": "abc",
        }
    )
    assert config.rule_id_bundle == {"tenant-a": "abc"}


def test_sentinel_one_config_loader_parses_correlation() -> None:
    config = load_sentinel_one_config(
        {
            "schema": "platform::sentinel_one::1.0",
            "status": "STAGING",
            "condition": {
                "type": "Correlation",
                "correlation": {
                    "entity": "host",
                    "match_in_order": True,
                    "time_window": "1h",
                    "sub_queries": [{"query": "a", "matches_required": 1}],
                },
            },
            "response": {"treat_as_threat": "Malicious", "network_quarantine": False},
        }
    )
    assert config.condition.correlation is not None
    assert config.condition.correlation.sub_queries[0].query == "a"
