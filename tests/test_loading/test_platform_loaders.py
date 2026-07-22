"""Per-platform configuration loaders."""

from __future__ import annotations

from opentide.loading.platform_loader import (
    load_carbon_black_config,
    load_crowdstrike_config,
    load_defender_config,
    load_sentinel_config,
    load_sentinel_one_config,
    load_splunk_config,
)
from opentide.models.platform import CarbonBlackConfig, SentinelConfig, SplunkConfig


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


def test_splunk_config_loader_normalizes_flat_v2_trigger_and_actions() -> None:
    config = load_splunk_config(
        {
            "schema": "splunk::2.1",
            "status": "STAGING",
            "query": "index=main | stats count",
            "scheduling": {"frequency": "1h", "lookback": "2h"},
            "throttling": {"duration": "1h", "fields": ["host"]},
            "threshold": 5,
            "notable": {"security_domain": "threat"},
            "risk": {"message": "risk message"},
        }
    )
    assert isinstance(config, SplunkConfig)
    assert config.query == "index=main | stats count"
    assert config.scheduling is not None
    assert config.scheduling.schedule is not None
    assert config.scheduling.schedule.frequency == "1h"
    assert config.scheduling.timerange is not None
    assert config.scheduling.timerange.lookback == "2h"
    assert config.trigger is not None
    assert config.trigger.threshold == 5
    assert config.trigger.throttling is not None
    assert config.trigger.throttling.duration == "1h"
    assert config.actions is not None
    assert config.actions.notable is not None
    assert config.actions.notable.security_domain == "threat"
    assert config.actions.risk is not None
    assert config.actions.risk.message == "risk message"


def test_splunk_config_loader_handles_missing_scheduling() -> None:
    config = load_splunk_config(
        {
            "schema": "splunk::3.0",
            "status": "STAGING",
            "query": "index=main",
            "trigger": {"threshold": 1},
        }
    )
    assert config.scheduling is None
    assert config.trigger is not None
    assert config.trigger.threshold == 1


def test_splunk_config_loader_ignores_unexpected_scheduling_keys() -> None:
    """Stray keys under scheduling (e.g. from stale index data) must not ValidationError."""
    config = load_splunk_config(
        {
            "schema": "splunk::3.0",
            "status": "STAGING",
            "query": "index=main",
            "scheduling": {
                "type": "Scheduled",
                "expires": "2h",
                "schedule": {"frequency": "1h"},
                "timerange": {"lookback": "2h"},
                "event": {"title": "should be ignored"},
            },
        }
    )
    assert config.scheduling is not None
    assert config.scheduling.type == "Scheduled"
    assert config.scheduling.expires == "2h"
    assert config.scheduling.schedule is not None
    assert config.scheduling.timerange is not None
    assert config.scheduling.timerange.lookback == "2h"


def test_carbon_black_config_loader_parses_typed_fields() -> None:
    config = load_carbon_black_config(
        {
            "schema": "carbon_black_cloud::3.0",
            "status": "STAGING",
            "query": "process_name:cmd.exe",
            "organizations": ["org-a"],
            "watchlist": "Default",
            "report": "Report A",
            "tags": ["tag-a"],
            "rule_id::org-a": "123",
        }
    )
    assert isinstance(config, CarbonBlackConfig)
    assert config.query == "process_name:cmd.exe"
    assert config.organizations == ["org-a"]
    assert config.watchlist == "Default"
    assert config.report == "Report A"
    assert config.tags == ["tag-a"]
    assert config.rule_id_bundle == {"org-a": "123"}
