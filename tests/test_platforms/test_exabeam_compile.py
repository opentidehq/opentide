"""An Exabeam block compiled to correlation rule bodies: goldens and derivations (exabeam-1.0)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.exabeam.compile import (
    compile_rule,
    create_request,
    derive_description,
    live_search_request,
    search_body,
    threshold_value,
    time_unit,
    update_request,
)

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "exabeam"
RULE_ID = "016dbc1d-a727-43df-a143-9546dcc81a5a"
SAMPLE_NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)

#: golden → (source rule, method, strategy), as the specification derives them.
GOLDENS = {
    "rule-exabeam-threshold-1.0.create.api.json": (
        "rule-exabeam-threshold-1.0.yaml",
        "POST",
        StatusStrategy.RELEASE,
    ),
    "rule-exabeam-threshold-1.0.update.api.json": (
        "rule-exabeam-threshold-1.0.yaml",
        "PUT",
        StatusStrategy.RELEASE,
    ),
    "rule-exabeam-threshold-1.0.disable.api.json": (
        "rule-exabeam-threshold-1.0.yaml",
        "PUT",
        StatusStrategy.DISABLEMENT,
    ),
    "rule-exabeam-sequence-1.0.create.api.json": (
        "rule-exabeam-sequence-1.0.yaml",
        "POST",
        StatusStrategy.RELEASE,
    ),
}


def _setup(**overrides: Any) -> SimpleNamespace:
    document = tomllib.loads((FIXTURES / "tenant.toml").read_text(encoding="utf-8"))
    return SimpleNamespace(**{**document["tenants"][0]["setup"], **overrides})


def _rule(name: str) -> DetectionRule:
    return load_rule_from_dict(yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8")))


def _block_rule(block: dict[str, Any], **rule: Any) -> DetectionRule:
    document: dict[str, Any] = {
        "name": "Failed logins",
        "metadata": {
            "uuid": "11111111-2222-4333-8444-555555555555",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "clear",
            "author": "Detection Engineering",
        },
        "description": "Failed logins.",
        "configurations": {
            "exabeam": {
                "enabled": True,
                "schema": "platform::exabeam::1.0",
                "status": "STAGING",
                "sequences": [{"query": 'activity_type:"app-login"'}],
                **block,
            }
        },
        **rule,
    }
    return load_rule_from_dict(document)


@pytest.mark.parametrize("golden", sorted(GOLDENS))
def test_the_goldens_byte_for_byte(golden: str) -> None:
    source, method, strategy = GOLDENS[golden]
    compiled = compile_rule(_rule(source), strategy, _setup())
    request = create_request(compiled) if method == "POST" else update_request(compiled, RULE_ID)
    text = (FIXTURES / golden).read_text(encoding="utf-8")
    assert request == json.loads(text)
    # Key order included: the bodies are sent in the order of the spec's table.
    assert json.dumps(request, indent=2, ensure_ascii=False) + "\n" == text


def test_the_live_golden() -> None:
    query = _rule("rule-exabeam-threshold-1.0.yaml").platform_configs().exabeam
    assert query is not None
    request = live_search_request(query.sequences[0].query, SAMPLE_NOW)
    text = (FIXTURES / "rule-exabeam-threshold-1.0.validate.api.json").read_text(encoding="utf-8")
    assert json.dumps(request, indent=2) + "\n" == text


def test_the_smallest_block() -> None:
    body = compile_rule(_rule("block-exabeam.yaml"), StatusStrategy.RELEASE).body
    assert list(body) == [
        "name",
        "description",
        "severity",
        "enabled",
        "testMode",
        "sequencesConfig",
        "suppressConfig",
        "delayConfig",
    ]
    assert body["sequencesConfig"] == {
        "sequences": [
            {
                "query": 'activity_type:"process-create" AND process_name:"mshta.exe"',
                "condition": {"triggerOnAnyMatch": True, "groupByOption": False, "groupBy": []},
            }
        ],
        "outcomes": {
            "sendAlertTriage": True,
            "createCase": False,
            "sendEmail": False,
            "alertTriage": {"name": "Exabeam correlation rule block"},
        },
    }
    assert body["description"].endswith("\n\nopentide: 00000000-0000-4000-8003-000000000070")
    assert "ATT&CK" not in body["description"]
    assert body["severity"] == "medium"


@pytest.mark.parametrize(
    ("block", "rule", "severity"),
    [
        ({"severity": "none"}, {"response": {"alert_severity": "Critical"}}, "none"),
        ({}, {"response": {"alert_severity": "Informational"}}, "none"),
        ({}, {"response": {"alert_severity": "Low"}}, "low"),
        ({}, {}, "medium"),
    ],
)
def test_severity(block: dict[str, Any], rule: dict[str, Any], severity: str) -> None:
    body = compile_rule(_block_rule(block, **rule), StatusStrategy.RELEASE).body
    assert body["severity"] == severity


def test_test_mode_block_then_tenant_then_false() -> None:
    rule = _block_rule({})
    assert compile_rule(rule, StatusStrategy.RELEASE).body["testMode"] is False
    assert compile_rule(rule, StatusStrategy.RELEASE, _setup(test_mode=True)).body["testMode"]
    forced = _block_rule({"test_mode": False})
    assert not compile_rule(forced, StatusStrategy.RELEASE, _setup(test_mode=True)).body["testMode"]


def test_name_and_outcomes() -> None:
    rule = _block_rule(
        {
            "name": "Exabeam name",
            "outcome": "none",
            "email": {"recipients": ["soc@example.com"], "subject": "Look"},
        }
    )
    body = compile_rule(rule, StatusStrategy.RELEASE).body
    assert body["name"] == "Exabeam name"
    assert body["sequencesConfig"]["outcomes"] == {
        "sendAlertTriage": False,
        "createCase": False,
        "sendEmail": True,
        "email": {"recipients": ["soc@example.com"], "subject": "Look", "attachCsv": False},
    }


def test_description_collapses_whitespace() -> None:
    rule = _block_rule({}, description="Two\n  lines\tof text.\n", techniques=["T1110.003"])
    assert derive_description(rule) == (
        "Two lines of text.\n\nATT&CK: T1110.003\nopentide: 11111111-2222-4333-8444-555555555555"
    )


def test_threshold_value_suppression_delay_and_schedule() -> None:
    rule = _block_rule(
        {
            "sequences": [
                {
                    "query": 'activity_type:"network-connection"',
                    "threshold": {
                        "function": "value",
                        "field": "dest_ip",
                        "operator": "not_in",
                        "value": ["0.0.0.0", "1.1.1.1"],
                        "within": "1d",
                    },
                }
            ],
            "suppression": {"for": "2w"},
            "delay": "2h",
            "schedule": [
                {"every": "day", "from": "00:00Z", "to": "23:59Z"},
                {"every": "week", "days": ["monday", "friday"], "from": "08:00Z", "to": "18:00Z"},
                {
                    "every": "month",
                    "days": [1, 15],
                    "from": "00:00Z",
                    "to": "06:00Z",
                },
            ],
        }
    )
    body = compile_rule(rule, StatusStrategy.RELEASE).body
    condition = body["sequencesConfig"]["sequences"][0]["condition"]
    assert condition["value"] == "0.0.0.0,1.1.1.1"
    assert (condition["subject"], condition["field"]) == ("field", "dest_ip")
    assert (condition["time"], condition["unit"]) == (1, "days")
    assert body["suppressConfig"] == {
        "suppressOption": True,
        "suppressTime": 2,
        "suppressUnit": "weeks",
    }
    assert body["delayConfig"] == {"delay": True, "delayTimeInMinutes": 120}
    assert body["scheduleConfig"]["recurrences"] == [
        {"recurrenceType": "DAILY", "startTime": "00:00Z", "endTime": "23:59Z"},
        {
            "recurrenceType": "WEEKLY",
            "startTime": "08:00Z",
            "endTime": "18:00Z",
            "daysOfWeek": ["MONDAY", "FRIDAY"],
        },
        {
            "recurrenceType": "MONTHLY",
            "startTime": "00:00Z",
            "endTime": "06:00Z",
            "daysInMonth": [1, 15],
            "lastDayOfMonth": False,
        },
    ]


@pytest.mark.parametrize(
    ("value", "text"),
    [(3, "3"), (2.5, "2.5"), (2.0, "2"), ([0.5, 2.0], "0.5,2"), (None, ""), (["a", 1], "a,1")],
)
def test_threshold_value(value: Any, text: str) -> None:
    assert threshold_value(value) == text


def test_time_unit_refuses_a_non_duration() -> None:
    assert time_unit("90m") == (90, "minutes")
    with pytest.raises(ValueError, match="not a duration"):
        time_unit("1h30m")


def test_search_body_reads_aware_times_as_utc() -> None:
    from datetime import timedelta

    paris = timezone(timedelta(hours=1))
    body = search_body(
        " q ",
        start=datetime(2026, 1, 1, 13, 0, tzinfo=paris),
        end=datetime(2026, 1, 1, 12, 30),  # noqa: DTZ001 -- a naive time is read as UTC
        limit=5,
        fields=["host"],
    )
    assert body == {
        "filter": "q",
        "fields": ["host"],
        "startTime": "2026-01-01T12:00:00Z",
        "endTime": "2026-01-01T12:30:00Z",
        "limit": 5,
    }


def test_a_rule_without_a_block_is_refused() -> None:
    rule = _block_rule({})
    other = rule.model_copy(update={"configurations": None})
    with pytest.raises(ValueError, match="has no"):
        compile_rule(other, StatusStrategy.RELEASE)


def test_the_offline_compiler_and_the_dry_run_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.deployment import preview

    rule = _rule("rule-exabeam-threshold-1.0.yaml")
    assert "exabeam" in preview.OFFLINE_COMPILERS
    assert preview.compile_offline("exabeam", rule) == _golden_request()
    shown = preview.preview_rule_deployment("exabeam", rule, [])
    assert shown["api_request"] == _golden_request()
    assert "tenant" not in shown
    tenant = SimpleNamespace(name="exabeam-eu", setup=_setup(test_mode=True))
    monkeypatch.setattr(preview, "_exabeam_tenant", lambda name: tenant if name else None)
    resolved = preview.preview_rule_deployment("exabeam", rule, ["exabeam-eu"])
    assert resolved["tenant"] == "exabeam-eu"
    assert resolved["api_request"]["body"]["testMode"] is True


def test_a_preview_that_cannot_compile_names_exabeam(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.deployment import preview

    def broken(*args: object, **kwargs: object) -> object:
        raise KeyError("sequences")

    monkeypatch.setattr(
        "opentide.platforms.exabeam.deployer.ExabeamDeploy.compile_deployment", broken
    )
    monkeypatch.setenv("DEPLOYMENT_ERROR_RAISED", "")
    result = preview.preview_rule_deployment(
        "exabeam", _rule("rule-exabeam-threshold-1.0.yaml"), []
    )
    assert result["code"] == "compile_failed"
    assert result["error"].startswith("Exabeam New-Scale SIEM cannot compile this rule")


def test_no_tenant_is_found_outside_a_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.deployment import preview

    assert preview._exabeam_tenant(None) is None
    monkeypatch.setattr(
        "opentide.core.registry.Opentide",
        SimpleNamespace(Configurations=SimpleNamespace(Systems=SimpleNamespace())),
    )
    assert preview._exabeam_tenant("exabeam-eu") is None


def _golden_request() -> dict[str, Any]:
    return json.loads(
        (FIXTURES / "rule-exabeam-threshold-1.0.create.api.json").read_text(encoding="utf-8")
    )
