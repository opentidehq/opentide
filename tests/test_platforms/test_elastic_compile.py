"""Tests for compiling OpenTide DetectionRule to Elastic Security rule body (RFC 0007 §3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from opentide.platforms.elastic.compile import compile_rule

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "elastic"

STAGING_SETUP = {
    "url": "https://soc-staging.kb.eu-west-1.aws.elastic.cloud",
    "elasticsearch_url": "https://soc-staging.es.eu-west-1.aws.elastic.cloud",
    "space": "staging",
    "api_key": "$ELASTIC_STAGING_API_KEY",
    "suppression": True,
}

PROD_SETUP = {
    "url": "https://kibana.soc.example.internal:5601",
    "elasticsearch_url": "https://es.soc.example.internal:9200",
    "space": "default",
    "api_key": "$ELASTIC_PROD_API_KEY",
    "index": ["logs-*", "winlogbeat-*"],
    "tags": ["soc-prod"],
    "suppression": False,
}


def _load_yaml_fixture(name: str) -> dict[str, Any]:
    return yaml.safe_load((FIXTURES_DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def _load_json_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / f"{name}.json").read_text(encoding="utf-8"))


def test_compile_example_a_matches_published_body() -> None:
    rule_dict = _load_yaml_fixture("rule-query")
    published = _load_json_fixture("body-query")
    compiled = compile_rule(rule_dict, STAGING_SETUP)
    assert compiled == published


def test_compile_example_b_eql() -> None:
    rule_dict = _load_yaml_fixture("rule-eql")
    compiled = compile_rule(rule_dict, STAGING_SETUP)
    assert compiled["type"] == "eql"
    assert compiled["language"] == "eql"
    assert compiled["from"] == "now-10m"
    assert compiled["interval"] == "5m"
    assert compiled["timestamp_field"] == "@timestamp"
    assert compiled["event_category_override"] == "event.category"
    assert compiled["tiebreaker_field"] == "event.sequence"


def test_compile_example_c_esql() -> None:
    rule_dict = _load_yaml_fixture("rule-esql")
    compiled = compile_rule(rule_dict, STAGING_SETUP)
    assert compiled["type"] == "esql"
    assert compiled["language"] == "esql"
    assert "index" not in compiled
    assert "data_view_id" not in compiled
    assert "filters" not in compiled
    assert compiled["from"] == "now-20m"
    assert compiled["interval"] == "15m"


def test_compile_example_d_threshold() -> None:
    rule_dict = _load_yaml_fixture("rule-threshold")
    compiled = compile_rule(rule_dict, STAGING_SETUP)
    assert compiled["type"] == "threshold"
    assert compiled["threshold"]["field"] == ["user.name"]
    assert compiled["threshold"]["value"] == 50
    assert compiled["threshold"]["cardinality"] == [{"field": "source.ip", "value": 8}]
    # Threshold alert_suppression has duration only, no group_by
    assert "group_by" not in compiled["alert_suppression"]
    assert compiled["alert_suppression"]["duration"] == {"value": 30, "unit": "m"}


def test_compile_example_e_new_terms() -> None:
    rule_dict = _load_yaml_fixture("rule-new-terms")
    compiled = compile_rule(rule_dict, STAGING_SETUP)
    assert compiled["type"] == "new_terms"
    assert compiled["new_terms_fields"] == ["user.name", "cloud.account.id"]
    assert compiled["history_window_start"] == "now-14d"
    assert compiled["from"] == "now-65m"
    # 1d suppression converted to 24h
    assert compiled["alert_suppression"]["duration"] == {"value": 24, "unit": "h"}


def test_compile_example_f_threat_match() -> None:
    rule_dict = _load_yaml_fixture("rule-threat")
    compiled = compile_rule(rule_dict, STAGING_SETUP)
    assert compiled["type"] == "threat_match"
    assert compiled["threat_index"] == ["logs-ti_abusech.malware-*", "logs-ti_misp.indicator-*"]
    assert compiled["threat_language"] == "kuery"
    assert compiled["threat_indicator_path"] == "threat.indicator"
    assert len(compiled["threat_mapping"]) == 2
    # Verify ATT&CK threat array was derived from techniques, not the YAML threat block
    assert "threat" in compiled
    assert any(t["tactic"]["id"] == "TA0002" for t in compiled["threat"])


def test_compile_example_g_machine_learning() -> None:
    rule_dict = _load_yaml_fixture("rule-ml")
    compiled = compile_rule(rule_dict, STAGING_SETUP)
    assert compiled["type"] == "machine_learning"
    assert "query" not in compiled
    assert "index" not in compiled
    assert "language" not in compiled
    assert compiled["machine_learning_job_id"] == [
        "high_count_network_events",
        "high_count_network_denies",
    ]
    assert compiled["anomaly_threshold"] == 75


def test_tenant_without_suppression_omits_alert_suppression() -> None:
    rule_dict = _load_yaml_fixture("rule-query")
    compiled = compile_rule(rule_dict, PROD_SETUP)
    assert "alert_suppression" not in compiled
    # Also verify tags ordering: OpenTide first, then tenant tags, then block tags
    assert compiled["tags"] == ["OpenTide", "soc-prod", "Windows", "LOLBAS"]


def test_never_send_id_or_version() -> None:
    rule_dict = _load_yaml_fixture("rule-query")
    compiled = compile_rule(rule_dict, STAGING_SETUP)
    assert "id" not in compiled
    assert "version" not in compiled
