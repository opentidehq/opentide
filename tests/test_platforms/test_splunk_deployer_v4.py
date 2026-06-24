"""Splunk MDRv4 deployer unit tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels


@pytest.fixture
def splunk_rule_payload(metadata: dict) -> dict:
    return {
        "name": "Splunk Rule",
        "metadata": metadata,
        "description": "Detect suspicious activity",
        "response": {"alert_severity": "High"},
        "configurations": {
            "splunk": {
                "schema": "splunk::3.0",
                "status": "STAGING",
                "query": "index=main | stats count by host",
                "scheduling": {
                    "schedule": {"frequency": "1h"},
                    "timerange": {"lookback": "2h"},
                },
                "trigger": {"threshold": 3},
                "actions": {
                    "notable": {"security_domain": "threat"},
                },
            }
        },
    }


@patch("opentide.platforms.splunk.deployer.techniques_resolver", return_value=[])
def test_config_mdr_v4_maps_scheduling_and_trigger(
    _mock_techniques: object, splunk_rule_payload: dict
) -> None:
    from opentide.platforms.splunk.deployer import SplunkDeploy

    deployer = SplunkDeploy.__new__(SplunkDeploy)
    deployer.TIMERANGE_MODE = "current"
    deployer.SKEWING_VALUE = 0
    deployer.OFFSET = 0
    deployer.ALERT_SEVERITY_MAPPING = {"High": 5}
    deployer.CORRELATION_SEARCHES = False

    rule = load_rule_from_dict(splunk_rule_payload)
    tenant_setup = ConfigurationModels.Systems.Splunk.Tenant.Setup(
        proxy=False,
        ssl=True,
        url="https://splunk.example",
        port=8089,
        app="search",
        enterprise_security=True,
        token="token",
    )

    config = deployer.config_mdr_v4(rule, tenant_setup)
    assert config["quantity"] == 3
    assert "cron_schedule" in config
    assert "dispatch.earliest_time" in config
    assert config["action.notable.param.security_domain"] == "threat"


def test_should_enable_correlation_search_prefers_mdr_override(splunk_rule_payload: dict) -> None:
    from opentide.platforms.splunk.deployer import SplunkDeploy

    deployer = SplunkDeploy.__new__(SplunkDeploy)
    deployer.CORRELATION_SEARCHES = True
    tenant_setup = ConfigurationModels.Systems.Splunk.Tenant.Setup(
        proxy=False,
        ssl=True,
        url="https://splunk.example",
        port=8089,
        app="search",
        enterprise_security=False,
        token="token",
    )
    rule = load_rule_from_dict(splunk_rule_payload)
    assert rule.configurations.splunk is not None
    from opentide.models.platform import SplunkConfig

    splunk_config = SplunkConfig(
        schema="splunk::3.0",
        status="STAGING",
        correlation_search=True,
    )
    assert deployer._should_enable_correlation_search(tenant_setup, splunk_config)


def test_is_action_allowed_gates_notable_on_enterprise_security() -> None:
    from opentide.platforms.splunk.deployer import SplunkDeploy

    deployer = SplunkDeploy.__new__(SplunkDeploy)
    tenant_setup = ConfigurationModels.Systems.Splunk.Tenant.Setup(
        proxy=False,
        ssl=True,
        url="https://splunk.example",
        port=8089,
        app="search",
        enterprise_security=False,
        token="token",
    )
    assert deployer._is_action_allowed("notable", tenant_setup) is False
    assert deployer._is_action_allowed("email", tenant_setup) is True
