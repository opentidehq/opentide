"""Splunk deployer unit tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels, SystemConfig


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


def _tenant(
    *,
    name: str = "Primary",
    enterprise_security: bool = True,
) -> ConfigurationModels.Systems.Splunk.Tenant:
    return ConfigurationModels.Systems.Splunk.Tenant(
        name=name,
        description="Primary tenant",
        deployment="ALWAYS",
        setup=ConfigurationModels.Systems.Splunk.Tenant.Setup(
            proxy=False,
            ssl=True,
            url="https://splunk.example",
            port=8089,
            app="search",
            enterprise_security=enterprise_security,
            token="token",
        ),
    )


def _deployer() -> object:
    from opentide.platforms.splunk.deployer import SplunkDeploy

    deployer = SplunkDeploy.__new__(SplunkDeploy)
    deployer.TIMERANGE_MODE = "current"
    deployer.SKEWING_VALUE = 0
    deployer.OFFSET = 0
    deployer.ALERT_SEVERITY_MAPPING = {"High": 5}
    deployer.CORRELATION_SEARCHES = False
    deployer.SPLUNK_ACTIONS = ["notable"]
    deployer.SPLUNK_DEFAULT_ACTIONS = ["notable"]
    deployer.DEFAULT_CONFIG = {}
    deployer.STATUS_MODIFIERS = []
    deployer.DEBUG_STEP = False
    return deployer


@patch("opentide.platforms.splunk.deployer.techniques_resolver", return_value=[])
def test_config_mdr_maps_scheduling_and_trigger(
    _mock_techniques: object, splunk_rule_payload: dict
) -> None:
    deployer = _deployer()
    rule = load_rule_from_dict(splunk_rule_payload)
    tenant = _tenant()

    config = deployer.config_mdr(rule, tenant.setup)
    assert config["quantity"] == 3
    assert "cron_schedule" in config
    assert "dispatch.earliest_time" in config
    assert config["action.notable.param.security_domain"] == "threat"


def test_should_enable_correlation_search_prefers_mdr_override(splunk_rule_payload: dict) -> None:
    from opentide.models.platform import SplunkConfig
    from opentide.platforms.splunk.deployer import SplunkDeploy

    deployer = SplunkDeploy.__new__(SplunkDeploy)
    deployer.CORRELATION_SEARCHES = True
    tenant = _tenant(enterprise_security=False)
    rule = load_rule_from_dict(splunk_rule_payload)
    assert rule.configurations.splunk is not None

    splunk_config = SplunkConfig(
        schema="splunk::3.0",
        status="STAGING",
        correlation_search=True,
    )
    assert deployer._should_enable_correlation_search(tenant.setup, splunk_config)


def test_is_action_allowed_gates_notable_on_enterprise_security() -> None:
    from opentide.platforms.splunk.deployer import SplunkDeploy

    deployer = SplunkDeploy.__new__(SplunkDeploy)
    tenant = _tenant(enterprise_security=False)
    assert deployer._is_action_allowed("notable", tenant.setup) is False
    assert deployer._is_action_allowed("email", tenant.setup) is True


@patch("opentide.platforms.splunk.deployer.techniques_resolver", return_value=[])
def test_default_modifier_does_not_clobber_lookback(
    _mock_techniques: object, splunk_rule_payload: dict
) -> None:
    """Platform Defaults with empty dispatch.earliest_time must not wipe lookback."""
    deployer = _deployer()
    rule = load_rule_from_dict(splunk_rule_payload)
    tenant = _tenant()

    deployer.STATUS_MODIFIERS = [
        SystemConfig.Modifiers(
            name="Platform Defaults",
            conditions=SystemConfig.Modifiers.Conditions(default=True),
            modifications={
                "dispatch.earliest_time": "",
                "dispatch.latest_time": "-5m@m",
            },
        )
    ]

    mdr_config = deployer.config_mdr(rule, tenant.setup)
    lookback = mdr_config["dispatch.earliest_time"]
    assert lookback  # lookback from rule scheduling

    allowed = deployer._apply_flat_modifiers(
        mdr_config=mdr_config, status="STAGING", tenant_config=tenant, flags=None
    )
    assert mdr_config["dispatch.earliest_time"] == lookback
    assert mdr_config["dispatch.latest_time"] == "-5m@m"
    assert "notable" in allowed


@patch("opentide.platforms.splunk.deployer.techniques_resolver", return_value=[])
def test_status_override_modifier_wins_over_rule_config(
    _mock_techniques: object, splunk_rule_payload: dict
) -> None:
    deployer = _deployer()
    rule = load_rule_from_dict(splunk_rule_payload)
    tenant = _tenant()

    deployer.STATUS_MODIFIERS = [
        SystemConfig.Modifiers(
            name="Staging Override",
            conditions=SystemConfig.Modifiers.Conditions(status=["STAGING"]),
            modifications={"dispatch.earliest_time": "-1h@h", "allowed_actions": False},
        )
    ]

    mdr_config = deployer.config_mdr(rule, tenant.setup)
    allowed = deployer._apply_flat_modifiers(
        mdr_config=mdr_config, status="STAGING", tenant_config=tenant, flags=None
    )
    assert mdr_config["dispatch.earliest_time"] == "-1h@h"
    assert allowed == []


@patch("opentide.platforms.splunk.deployer.techniques_resolver", return_value=[])
def test_flag_modifier_requires_matching_flag(
    _mock_techniques: object, splunk_rule_payload: dict
) -> None:
    deployer = _deployer()
    rule = load_rule_from_dict(splunk_rule_payload)
    tenant = _tenant()
    deployer.STATUS_MODIFIERS = [
        SystemConfig.Modifiers(
            name="Flagged Override",
            conditions=SystemConfig.Modifiers.Conditions(flags=["canary"]),
            modifications={"dispatch.earliest_time": "-30m@m"},
        )
    ]

    mdr_config = deployer.config_mdr(rule, tenant.setup)
    lookback = mdr_config["dispatch.earliest_time"]
    deployer._apply_flat_modifiers(
        mdr_config=mdr_config, status="STAGING", tenant_config=tenant, flags=None
    )
    assert mdr_config["dispatch.earliest_time"] == lookback

    deployer._apply_flat_modifiers(
        mdr_config=mdr_config,
        status="STAGING",
        tenant_config=tenant,
        flags=["canary"],
    )
    assert mdr_config["dispatch.earliest_time"] == "-30m@m"


@patch("opentide.platforms.splunk.deployer.create_query", return_value="index=main")
@patch("opentide.platforms.splunk.deployer.techniques_resolver", return_value=[])
def test_deploy_mdr_applies_modifiers_before_saved_search(
    _mock_techniques: object,
    _mock_query: object,
    splunk_rule_payload: dict,
) -> None:
    deployer = _deployer()
    rule = load_rule_from_dict(splunk_rule_payload)
    tenant = _tenant()
    deployer.STATUS_MODIFIERS = [
        SystemConfig.Modifiers(
            name="Platform Defaults",
            conditions=SystemConfig.Modifiers.Conditions(default=True),
            modifications={"dispatch.earliest_time": "", "dispatch.latest_time": "-5m@m"},
        )
    ]

    service = MagicMock()
    service.saved_searches = MagicMock()
    service.saved_searches.__getitem__.side_effect = KeyError("missing")
    created = MagicMock()
    service.saved_searches.create.return_value = created

    result = deployer.deploy_mdr(data=rule, service=service, tenant_config=tenant)
    assert result is True
    # First-stage update kwargs should keep lookback and include latest_time default.
    first_update = created.update.call_args_list[0].kwargs
    assert first_update.get("dispatch.earliest_time")
    assert first_update.get("dispatch.latest_time") == "-5m@m"
