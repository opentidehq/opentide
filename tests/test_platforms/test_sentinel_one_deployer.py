"""SentinelOne custom detection rule payloads."""

from __future__ import annotations

from dataclasses import asdict

import pytest

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.system_config import ConfigurationModels

Tenant = ConfigurationModels.Systems.SentinelOne.Tenant
TENANT = Tenant(
    name="Primary",
    description="",
    setup=Tenant.Setup(ssl=True, url="https://s1.example", account_id=1, api_token="token"),
)


@pytest.fixture(autouse=True)
def _staging_is_released(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "opentide.platforms.sentinel_one.deployer.check_status",
        lambda _status: StatusStrategy.RELEASE,
    )


def _payload(metadata: dict, cool_off: str | None) -> dict:
    from opentide.platforms.sentinel_one.deployer import SentinelOneDeploy

    rule = load_rule_from_dict(
        {
            "name": "S1 rule",
            "metadata": metadata,
            "description": "desc",
            "response": {"alert_severity": "High"},
            "configurations": {
                "sentinel_one": {
                    "schema": "sentinel_one::1.0",
                    "status": "STAGING",
                    "condition": {
                        "type": "Single Event",
                        "single_event": {"query": 'EventType = "Process Create"'},
                        "cool_off": cool_off,
                    },
                }
            },
        }
    )
    return asdict(SentinelOneDeploy().compile_deployment(data=rule, tenant_config=TENANT))


@pytest.mark.parametrize(("cool_off", "minutes"), [("30m", 30), ("2h", 120)])
def test_cool_off_is_sent_in_minutes(metadata: dict, cool_off: str, minutes: int) -> None:
    """``cool_off is str`` is always false, so the raw ``"30m"`` was sent instead."""
    payload = _payload(metadata, cool_off)
    assert payload["data"]["coolOffSetting"] == {"renotifyMinutes": minutes}


def test_no_cool_off_sends_none(metadata: dict) -> None:
    assert _payload(metadata, None)["data"]["coolOffSetting"] is None


def test_a_cool_off_without_a_unit_is_refused_by_name(metadata: dict) -> None:
    with pytest.raises(ValueError, match=r"minutes \(30m\) or hours \(2h\), got '1d'"):
        _payload(metadata, "1d")
