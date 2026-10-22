"""Tests for ElasticConfig and its constraint validators (RFC 0007 §2)."""

from __future__ import annotations

import pytest
import yaml

from opentide.models.platform import ElasticConfig


def test_elastic_config_omitted_status_is_rejected() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as caught:
        ElasticConfig.model_validate(
            {
                "type": "query",
                "query": "process.name: *",
                "index": ["logs-*"],
            }
        )
    missing_status = [
        error
        for error in caught.value.errors()
        if error["loc"] == ("status",) and error["type"] == "missing"
    ]
    assert missing_status


def test_elastic_config_invalid_rfc_block_reports_all_three_codes() -> None:
    raw_yaml = """
elastic:
  enabled: true
  schema: platform::elastic::1.0
  status: STAGING
  type: esql
  language: kuery
  query: FROM logs-* | LIMIT 10
  index: [logs-*]
  suppression: {duration: 1h}
"""
    block = yaml.safe_load(raw_yaml)["elastic"]
    with pytest.raises(ValueError) as excinfo:
        ElasticConfig.model_validate(block)
    msg = str(excinfo.value)
    assert "esql_source" in msg
    assert "language" in msg
    assert "suppression_shape" in msg


@pytest.mark.parametrize(
    ("constraint_code", "block"),
    [
        (
            "type_block",
            {"type": "query", "query": "x", "threshold": {"field": [], "value": 1}},
        ),
        (
            "type_block",
            {"type": "query", "query": "x", "interval": "5m"},  # retired flat key
        ),
        (
            "type_block",
            {"type": "query", "query": "x", "alert_suppression": {"duration": "1h"}},
        ),
        (
            "language",
            {"type": "eql", "query": "x", "language": "kuery"},
        ),
        (
            "esql_source",
            {"type": "esql", "query": "FROM x", "data_view_id": "d"},
        ),
        (
            "index_xor_data_view",
            {"type": "query", "query": "x", "index": ["a"], "data_view_id": "d"},
        ),
        (
            "index_list",
            {"type": "query", "query": "x", "index": "logs-*"},  # string instead of list
        ),
        (
            "suppression_shape",
            {
                "type": "threshold",
                "query": "x",
                "threshold": {"field": [], "value": 1},
                "suppression": {"group_by": ["a"], "duration": "1h"},
            },
        ),
        (
            "new_terms_fields",
            {
                "type": "new_terms",
                "query": "x",
                "new_terms": {"fields": ["a", "b", "c", "d"], "history_window_start": "7d"},
            },
        ),
        (
            "threshold_fields",
            {"type": "threshold", "query": "x", "threshold": {"field": [], "value": 0}},
        ),
        (
            "risk_score",
            {"type": "query", "query": "x", "risk": {"score": 101}},
        ),
        (
            "duration",
            {"type": "query", "query": "x", "scheduling": {"interval": "5min", "lookback": "1m"}},
        ),
        (
            "filter_shape",
            {
                "type": "query",
                "query": "x",
                "filters": [{"field": "a", "value": "b", "meta": {}}],
            },
        ),
        (
            "exception_type",
            {
                "type": "query",
                "query": "x",
                "exceptions": {
                    "lists": [
                        {
                            "id": "1",
                            "list_id": "l1",
                            "namespace_type": "single",
                            "type": "invalid_type",
                        }
                    ]
                },
            },
        ),
        (
            "response_action",
            {
                "type": "query",
                "query": "x",
                "actions": {
                    "respond": [
                        {"endpoint": "reboot-now"}  # invalid command
                    ]
                },
            },
        ),
    ],
)
def test_elastic_config_constraint_codes(constraint_code: str, block: dict) -> None:
    with pytest.raises(ValueError) as excinfo:
        ElasticConfig.model_validate({"status": "STAGING", **block})
    assert constraint_code in str(excinfo.value)


def test_elastic_machine_learning_job_id_passthrough() -> None:
    # Single string job_id
    config_single = ElasticConfig.model_validate(
        {
            "status": "STAGING",
            "type": "machine_learning",
            "machine_learning": {
                "job_id": "rare_process_by_host",
                "anomaly_threshold": 50,
            },
        }
    )
    assert config_single.machine_learning.job_id == "rare_process_by_host"

    # List job_id
    config_list = ElasticConfig.model_validate(
        {
            "status": "STAGING",
            "type": "machine_learning",
            "machine_learning": {
                "job_id": ["job_one", "job_two"],
                "anomaly_threshold": 75,
            },
        }
    )
    assert config_list.machine_learning.job_id == ["job_one", "job_two"]


_BASE = {"status": "STAGING", "type": "query", "query": "process.name: *"}


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"actions": {"respond": [{"osquery": {"timeout": 60}}]}}, "response_action"),
        ({"actions": {"respond": [{"endpoint": "isolate", "bogus": 1}]}}, "response_action"),
        (
            {"actions": {"respond": [{"action_type_id": ".osquery", "params": {}}]}},
            "response_action",
        ),
        ({"filters": [{}]}, "filter_shape"),
        ({"filters": [{"meta": {}}]}, "filter_shape"),
        # A raw filter carries its negation in meta.negate; a top-level negate
        # mixes the two shapes, and Kibana would ignore it (RFC 0007 filter_shape).
        (
            {"filters": [{"meta": {"negate": False}, "query": {"match_all": {}}, "negate": True}]},
            "filter_shape",
        ),
        ({"severity": "Hgh"}, "severity"),
        ({"severity": {"default": "urgent"}}, "severity"),
        ({"suppression": "1h"}, "suppression_shape"),
        ({"suppression": {"group_by": "host.name"}}, "suppression_shape"),
        (
            {"type": "threshold", "threshold": {"value": "x"}, "suppression": {"duration": "1h"}},
            "threshold_fields",
        ),
        (
            {
                "type": "new_terms",
                "new_terms": {"fields": "user.name", "history_window_start": "14d"},
            },
            "new_terms_fields",
        ),
    ],
)
def test_elastic_config_rejects_with_a_code_not_a_crash(overrides: dict, code: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match=code):
        ElasticConfig.model_validate({**_BASE, **overrides})


@pytest.mark.parametrize("severity", ["Informational", "low", "High", {"default": "Critical"}])
def test_elastic_config_accepts_alert_severity_vocabulary(severity: object) -> None:
    ElasticConfig.model_validate({**_BASE, "severity": severity})


@pytest.mark.parametrize(
    "overrides",
    [
        {"scheduling": {"interval": ""}},
        {"scheduling": {"lookback": ""}},
        {"suppression": {"group_by": ["host.name"], "duration": ""}},
        {
            "type": "threshold",
            "threshold": {"field": ["host.name"], "value": 5},
            "suppression": {"duration": ""},
        },
        {"type": "new_terms", "new_terms": {"fields": ["user.name"], "history_window_start": ""}},
    ],
)
def test_elastic_config_empty_duration_reports_duration(overrides: dict) -> None:
    # #589: "" used to skip the duration check, pass validate and crash compile.
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="duration"):
        ElasticConfig.model_validate({**_BASE, **overrides})


@pytest.mark.parametrize("scheduling", ["5m", ["5m"], 5])
def test_elastic_config_non_object_scheduling_is_a_shape_error(scheduling: object) -> None:
    # #589: a non-object scheduling block is a shape fault, not a `duration` one.
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as excinfo:
        ElasticConfig.model_validate({**_BASE, "scheduling": scheduling})
    message = str(excinfo.value)
    assert "scheduling" in message
    assert "duration" not in message


@pytest.mark.parametrize(
    "overrides",
    [
        {"scheduling": {"interval": "５m"}},  # fullwidth 5
        {"scheduling": {"lookback": "٣h"}},  # Arabic-Indic 3
        {"suppression": {"group_by": ["host.name"], "duration": "PT١H"}},
    ],
)
def test_elastic_config_non_ascii_digits_report_duration(overrides: dict) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="duration"):
        ElasticConfig.model_validate({**_BASE, **overrides})


def test_elastic_config_roundtrips_through_exclude_none_false_dump() -> None:
    """TideDeployment.modifiers_resolver re-validates model_dump(exclude_none=False)."""
    from pathlib import Path

    from opentide.loading.rule_loader import load_rule_from_dict

    fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures" / "elastic"
    for path in sorted(fixtures_dir.glob("rule-*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        rule = load_rule_from_dict(raw)
        dumped = rule.model_dump(by_alias=True, exclude_none=False)
        reloaded = load_rule_from_dict(dumped)
        assert reloaded.configurations.elastic is not None
        assert reloaded.configurations.elastic.type == rule.configurations.elastic.type
