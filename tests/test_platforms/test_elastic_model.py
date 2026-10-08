"""Tests for ElasticConfig and its constraint validators (RFC 0007 §2)."""

from __future__ import annotations

import pytest
import yaml

from opentide.models.platform import ElasticConfig


def test_elastic_config_omitted_status_defaults_to_staging() -> None:
    config = ElasticConfig.model_validate(
        {
            "type": "query",
            "query": "process.name: *",
            "index": ["logs-*"],
        }
    )
    assert config.status == "STAGING"
    assert config.type == "query"


def test_elastic_config_invalid_rfc_block_reports_all_three_codes() -> None:
    raw_yaml = """
elastic:
  enabled: true
  schema: platform::elastic::1.0
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
        ElasticConfig.model_validate(block)
    assert constraint_code in str(excinfo.value)


def test_elastic_machine_learning_job_id_passthrough() -> None:
    # Single string job_id
    config_single = ElasticConfig.model_validate(
        {
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
            "type": "machine_learning",
            "machine_learning": {
                "job_id": ["job_one", "job_two"],
                "anomaly_threshold": 75,
            },
        }
    )
    assert config_list.machine_learning.job_id == ["job_one", "job_two"]
