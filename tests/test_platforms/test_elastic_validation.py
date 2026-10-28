"""Tests for ElasticValidator and Elasticsearch checks (RFC 0007 §6)."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic import advisories as elastic_advisories
from opentide.platforms.elastic import attack as elastic_attack
from opentide.platforms.elastic import validator as elastic_validator
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.es_checks import (
    ElasticRuleCheckError,
    ElasticTenantError,
    esql_from_sources,
    resolve_rule_sources,
    run_aggregation_fields_check,
    run_esql_preflight,
    run_threat_match_fields_check,
    run_timestamp_fields_check,
)
from opentide.platforms.elastic.validator import ElasticValidator


def _mock_response(status_code: int = 200, json_data: dict | list | None = None, text: str = ""):
    resp = requests.Response()
    resp.status_code = status_code
    if json_data is not None:
        resp._content = json.dumps(json_data).encode("utf-8")
        resp.headers["content-type"] = "application/json"
    else:
        resp._content = text.encode("utf-8")
    return resp


def test_esql_preflight_parsing_exception_fails_rule() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    with patch.object(client.session, "post") as mock_post:
        mock_post.return_value = _mock_response(
            400,
            json_data={
                "error": {
                    "type": "parsing_exception",
                    "reason": "line 1:20: mismatched input 'WHER'",
                }
            },
        )
        with pytest.raises(ValueError, match="ES\\|QL parsing exception"):
            run_esql_preflight(client, "FROM logs-* | WHER process.name == 'test'")


def test_esql_preflight_unonboarded_sources_warns_and_passes() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    with (
        patch.object(client.session, "post") as mock_post,
        patch.object(client.session, "get") as mock_get,
    ):
        mock_post.return_value = _mock_response(
            400,
            json_data={
                "error": {
                    "type": "verification_exception",
                    "reason": "Unknown index [logs-*]",
                }
            },
        )
        mock_get.return_value = _mock_response(
            200,
            json_data={"indices": [], "aliases": [], "data_streams": []},
        )
        # Should not raise, returns empty columns
        columns = run_esql_preflight(client, "FROM logs-* | WHERE process.name == 'test'")
        assert columns == []


def test_aggregation_fields_check_misspelt_field_fails() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "threshold",
        "threshold": {"field": ["source.misspelt"], "value": 5},
        "index": ["logs-*"],
    }
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={
                "indices": ["logs-2026.10"],
                "fields": {
                    "source.ip": {"ip": {"aggregatable": True}},
                },
            },
        )
        with pytest.raises(ValueError, match=r"Field 'source\.misspelt' not found in mappings"):
            run_aggregation_fields_check(client, block)


def test_aggregation_fields_check_non_aggregatable_field_fails() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "threshold",
        "threshold": {"field": ["message"], "value": 5},
        "index": ["logs-*"],
    }
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={
                "indices": ["logs-2026.10"],
                "fields": {
                    "message": {"text": {"aggregatable": False}},
                },
            },
        )
        with pytest.raises(ValueError, match="Field 'message' is not aggregatable"):
            run_aggregation_fields_check(client, block)


def test_aggregation_fields_check_unonboarded_sources_warns_and_passes() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "threshold",
        "threshold": {"field": ["source.ip"], "value": 5},
        "index": ["logs-*"],
    }
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={
                "indices": [],
                "fields": {},
            },
        )
        # Should not raise exception
        run_aggregation_fields_check(client, block)


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks")
def test_validator_preview_reports_log_errors(mock_checks, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.delenv("VALIDATION_WARNING_RAISED", raising=False)
    mock_checks.return_value = []
    setup = ConfigurationModels.Systems.Elastic.Tenant.Setup(
        ssl=True,
        url="https://kibana.test:5601",
        elasticsearch_url="https://es.test:9200",
        api_key="test-key",
        space="default",
    )
    tenant = ConfigurationModels.Systems.Elastic.Tenant(
        name="test-tenant",
        description="test",
        setup=setup,
    )
    raw = {
        "name": "Preview Broken Rule",
        "metadata": {
            "uuid": "00000000-0000-4000-8003-000000000009",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "clear",
            "author": "Author",
        },
        "description": "Test description",
        "techniques": [],
        "response": {"alert_severity": "High"},
        "configurations": {
            "elastic": {
                "enabled": True,
                "schema": "platform::elastic::1.0",
                "status": "STAGING",
                "type": "query",
                "query": "process.name: *",
                "index": ["logs-*"],
            }
        },
    }
    from opentide.loading.rule_loader import load_rule_from_dict

    rule = load_rule_from_dict(raw)
    batch = MagicMock(tenant=tenant, rules=[rule])

    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(
            200,
            json_data={"logs": [{"errors": ["Unknown field 'foo.bar' in query"]}]},
        )
        validator.validate([rule])
        assert os.environ.get("VALIDATION_ERROR_RAISED") == "1"


def _clear_validation_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.delenv("VALIDATION_WARNING_RAISED", raising=False)


def _elastic_rule(
    name: str,
    uuid: str,
    *,
    rule_type: str = "query",
    query: str | None = "process.name: *",
    interval: str = "5m",
    lookback: str | None = None,
    index: list[str] | None = None,
    overrides: dict | None = ...,
    risk: int | dict | None = None,
    suppression: dict | None = None,
    threshold: dict | None = None,
    machine_learning: dict | None = None,
    techniques: list[str] | None = None,
    alert_severity: str = "High",
) -> object:
    from opentide.loading.rule_loader import load_rule_from_dict

    elastic: dict = {
        "enabled": True,
        "schema": "platform::elastic::1.0",
        "status": "STAGING",
        "type": rule_type,
    }
    if rule_type != "machine_learning" and query is not None:
        elastic["query"] = query
    if rule_type not in ("esql", "machine_learning"):
        elastic["index"] = index or ["logs-*"]
    if lookback is not None or interval != "5m":
        elastic["scheduling"] = {"interval": interval, "lookback": lookback or "1m"}
    if overrides is ...:
        if rule_type != "machine_learning":
            elastic["overrides"] = {"timestamp": "event.ingested"}
    elif overrides is not None:
        elastic["overrides"] = overrides
    if risk is not None:
        elastic["risk"] = risk
    if suppression is not None:
        elastic["suppression"] = suppression
    if threshold is not None:
        elastic["threshold"] = threshold
    if machine_learning is not None:
        elastic["machine_learning"] = machine_learning
    return load_rule_from_dict(
        {
            "name": name,
            "metadata": {
                "uuid": uuid,
                "schema": "rule::1.0",
                "version": 1,
                "created": "2026-01-01",
                "modified": "2026-01-02",
                "tlp": "clear",
                "author": "Author",
            },
            "description": "Test description",
            "techniques": techniques or [],
            "response": {"alert_severity": alert_severity},
            "configurations": {"elastic": elastic},
        }
    )


def _tenant() -> ConfigurationModels.Systems.Elastic.Tenant:
    setup = ConfigurationModels.Systems.Elastic.Tenant.Setup(
        ssl=True,
        url="https://kibana.test:5601",
        elasticsearch_url="https://es.test:9200",
        api_key="test-key",
        space="default",
    )
    return ConfigurationModels.Systems.Elastic.Tenant(
        name="test-tenant",
        description="test",
        setup=setup,
    )


def test_esql_from_sources_stops_before_metadata() -> None:
    query = 'FROM logs-* METADATA _id, _version | WHER process.name == "test"'
    assert esql_from_sources(query) == "logs-*"


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (
            "// Detects logins from rare countries\n"
            "FROM logs-system.auth-* METADATA _id\n| WHERE x",
            "logs-system.auth-*",
        ),
        (
            "FROM logs-endpoint.events.process-*,\n"
            "  logs-windows.sysmon_operational-* METADATA _id\n| LIMIT 1",
            "logs-endpoint.events.process-*,logs-windows.sysmon_operational-*",
        ),
        ("/* from x */ FROM logs-* | LIMIT 1", "logs-*"),
        ("/* a /* FROM b */ c */ FROM logs-* | LIMIT 1", "logs-*"),
        ("TS metrics-* | STATS max(x)", "metrics-*"),
        ("from logs-a, // logs-b\n  logs-c\n| LIMIT 1", "logs-a,logs-c"),
        ('FROM "logs-*", remote:logs-*::failures | LIMIT 1', "logs-*,remote:logs-*::failures"),
        ('FROM """logs-*""" METADATA _id', "logs-*"),
        ("ROW x = 1 | EVAL y = 2", ""),
        ("// FROM logs-*\nROW x = 1", ""),
    ],
)
def test_esql_from_sources_reads_the_source_command(query: str, expected: str) -> None:
    assert esql_from_sources(query) == expected


def test_esql_preflight_metadata_query_parsing_exception_fails() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    query = 'FROM logs-* METADATA _id, _version | WHER process.name == "test"'
    with patch.object(client.session, "post") as mock_post:
        mock_post.return_value = _mock_response(
            400,
            json_data={
                "error": {
                    "type": "parsing_exception",
                    "reason": "line 1:20: mismatched input 'WHER'",
                }
            },
        )
        with pytest.raises(ValueError, match="ES\\|QL parsing exception"):
            run_esql_preflight(client, query)


def test_esql_preflight_verification_resolves_sources_without_metadata() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    query = 'FROM logs-* METADATA _id, _version | WHER process.name == "test"'
    with (
        patch.object(client.session, "post") as mock_post,
        patch.object(client.session, "get") as mock_get,
    ):
        mock_post.return_value = _mock_response(
            400,
            json_data={
                "error": {
                    "type": "verification_exception",
                    "reason": "Unknown index [logs-*]",
                }
            },
        )
        mock_get.return_value = _mock_response(
            200,
            json_data={"indices": [], "aliases": [], "data_streams": []},
        )
        assert run_esql_preflight(client, query) == []
        requested = mock_get.call_args[0][0]
        assert "/_resolve/index/logs-%2A" in requested
        assert "METADATA" not in requested


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_checks_every_rule_when_the_first_preview_fails(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    first = _elastic_rule("First", "00000000-0000-4000-8003-000000000001")
    second = _elastic_rule("Second", "00000000-0000-4000-8003-000000000002")
    batch = MagicMock(tenant=_tenant(), rules=[first, second])
    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.side_effect = [
            _mock_response(200, json_data={"logs": [{"errors": ["bad query"]}]}),
            _mock_response(200, json_data={"logs": []}),
        ]
        validator.validate([first, second])
    assert mock_preview.call_count == 2
    assert os.environ.get("VALIDATION_ERROR_RAISED") == "1"


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_warnings_set_the_warning_flag(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    rule = _elastic_rule(
        "Lookback",
        "00000000-0000-4000-8003-000000000003",
        rule_type="esql",
        query="FROM logs-* | WHERE process.name == 'x'",
        lookback="0m",
    )
    batch = MagicMock(tenant=_tenant(), rules=[rule])
    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(
            200,
            json_data={"logs": [{"warnings": ["index logs-* does not exist"]}]},
        )
        validator.validate([rule])
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"
    assert os.environ.get("VALIDATION_ERROR_RAISED") is None


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_lowercase_metadata_id_does_not_warn(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    rule = _elastic_rule(
        "Deduped",
        "00000000-0000-4000-8003-000000000004",
        rule_type="esql",
        query="FROM logs-* metadata _id | WHERE process.name == 'x'",
    )
    batch = MagicMock(tenant=_tenant(), rules=[rule])
    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        validator.validate([rule])
    assert os.environ.get("VALIDATION_WARNING_RAISED") is None


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_preview_403_skips_the_rest_of_the_tenant(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    first = _elastic_rule("Denied", "00000000-0000-4000-8003-000000000005")
    second = _elastic_rule("Later", "00000000-0000-4000-8003-000000000006")
    batch = MagicMock(tenant=_tenant(), rules=[first, second])
    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(403, text="forbidden")
        validator.validate([first, second])
    assert mock_preview.call_count == 1
    assert os.environ.get("VALIDATION_ERROR_RAISED") == "1"


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_does_not_warn_when_timestamp_override_is_omitted(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    """overrides.timestamp is optional in RFC 0007 §2; the RFC template omits it."""
    _clear_validation_flags(monkeypatch)
    rule = _elastic_rule(
        "No Timestamp Override",
        "00000000-0000-4000-8003-000000000007",
        overrides=None,
    )
    batch = MagicMock(tenant=_tenant(), rules=[rule])
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        ElasticValidator().validate([rule])
    assert os.environ.get("VALIDATION_WARNING_RAISED") is None


@pytest.mark.parametrize(
    ("rule_type", "interval", "lookback", "threshold_cfg"),
    [
        ("query", "5m", "0s", None),
        ("query", "5m", "PT0S", None),
        ("query", "5m", "2h", None),
        ("threshold", "5m", "10m", {"field": ["user.name"], "value": 5}),
    ],
)
@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_warns_on_zero_or_long_lookback(
    _mock_checks,
    monkeypatch: pytest.MonkeyPatch,
    rule_type: str,
    interval: str,
    lookback: str,
    threshold_cfg: dict | None,
) -> None:
    _clear_validation_flags(monkeypatch)
    rule = _elastic_rule(
        "Schedule Check",
        "00000000-0000-4000-8003-000000000010",
        rule_type=rule_type,
        interval=interval,
        lookback=lookback,
        threshold=threshold_cfg,
    )
    batch = MagicMock(tenant=_tenant(), rules=[rule])
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        ElasticValidator().validate([rule])
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_warns_when_risk_score_outside_severity_band(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    # High severity expects 48-73; 20 is in the low band
    out_of_band = _elastic_rule(
        "Mismatched Risk",
        "00000000-0000-4000-8003-000000000011",
        alert_severity="High",
        risk=20,
    )
    batch = MagicMock(tenant=_tenant(), rules=[out_of_band])
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        ElasticValidator().validate([out_of_band])
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"

    _clear_validation_flags(monkeypatch)
    in_band = _elastic_rule(
        "Matched Risk",
        "00000000-0000-4000-8003-000000000012",
        alert_severity="High",
        risk=68,
    )
    batch_ok = MagicMock(tenant=_tenant(), rules=[in_band])
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch_ok]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        ElasticValidator().validate([in_band])
    assert os.environ.get("VALIDATION_WARNING_RAISED") is None


@pytest.mark.parametrize(
    ("maxspan", "interval", "lookback", "should_warn"),
    [
        ("15m", "5m", "1m", True),  # maxspan > interval + lookback
        ("3m", "5m", "1m", True),  # maxspan > lookback
        ("2m", "5m", "5m", False),  # maxspan <= lookback
        ("500ms", "5m", "1m", False),  # milliseconds, not minutes
        ("90000ms", "5m", "1m", True),  # 90s > lookback
        ("2 m", "5m", "5m", False),  # space between number and unit
    ],
)
@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_eql_maxspan_vs_schedule_window(
    _mock_checks,
    monkeypatch: pytest.MonkeyPatch,
    maxspan: str,
    interval: str,
    lookback: str,
    should_warn: bool,
) -> None:
    _clear_validation_flags(monkeypatch)
    query = (
        f"sequence by host.id with maxspan={maxspan}\n"
        '  [process where event.type == "start"]\n'
        '  [network where event.type == "start"]'
    )
    rule = _elastic_rule(
        "EQL Sequence",
        "00000000-0000-4000-8003-000000000013",
        rule_type="eql",
        query=query,
        interval=interval,
        lookback=lookback,
    )
    batch = MagicMock(tenant=_tenant(), rules=[rule])
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        ElasticValidator().validate([rule])
    if should_warn:
        assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"
    else:
        assert os.environ.get("VALIDATION_WARNING_RAISED") is None


def _run_validator(rule: object) -> None:
    batch = MagicMock(tenant=_tenant(), rules=[rule])
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        ElasticValidator().validate([rule])


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_eql_reads_the_header_maxspan(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    query = (
        "sequence by host.id with maxspan=15m\n"
        '  [process where process.name : "a.exe"] // maxspan=1s in a comment\n'
        "  [network where true]"
    )
    _run_validator(
        _elastic_rule(
            "EQL Two Maxspans",
            "00000000-0000-4000-8003-000000000016",
            rule_type="eql",
            query=query,
            lookback="1m",
        )
    )
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_eql_maxspan_in_a_string_is_not_a_sequence(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    _run_validator(
        _elastic_rule(
            "EQL Event Query",
            "00000000-0000-4000-8003-000000000017",
            rule_type="eql",
            query='process where process.name : "sequence.exe" and process.args : "maxspan=1d"',
            lookback="1m",
        )
    )
    assert os.environ.get("VALIDATION_WARNING_RAISED") is None


@pytest.mark.parametrize(
    ("query", "should_warn"),
    [
        ("FROM logs-* | INLINE STATS c = COUNT(*) BY host.name | WHERE c > 5", True),
        ("FROM logs-* | INLINESTATS c = COUNT(*) BY host.name | WHERE c > 5", True),
        ("// add METADATA _id later\nFROM logs-* | WHERE x", True),
        ('FROM logs-* | WHERE message == "| STATS c = COUNT(*)"', True),
        ("FROM logs-* | STATS c = COUNT(*) BY host.name", False),
        ("FROM logs-* METADATA _id | INLINE STATS c = COUNT(*) BY host.name", False),
    ],
)
@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_esql_metadata_id_warning_reads_past_comments_and_inline_stats(
    _mock_checks, monkeypatch: pytest.MonkeyPatch, query: str, should_warn: bool
) -> None:
    _clear_validation_flags(monkeypatch)
    _run_validator(
        _elastic_rule(
            "ES|QL Dedup",
            "00000000-0000-4000-8003-000000000018",
            rule_type="esql",
            query=query,
            lookback="1m",
        )
    )
    if should_warn:
        assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"
    else:
        assert os.environ.get("VALIDATION_WARNING_RAISED") is None


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_warns_on_basic_license_suppression_and_ics_technique(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    tenant = _tenant()
    tenant.setup.suppression = False
    rule = _elastic_rule(
        "Basic Tenant Rule",
        "00000000-0000-4000-8003-000000000014",
        suppression={"group_by": ["host.name"], "duration": "1h"},
    )
    batch = MagicMock(tenant=tenant, rules=[rule])
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        ElasticValidator().validate([rule])
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"

    # Non-Enterprise ATT&CK technique (T0807 is ICS) sets warning flag
    _clear_validation_flags(monkeypatch)
    ics_rule = _elastic_rule(
        "ICS Technique Rule",
        "00000000-0000-4000-8003-000000000015",
        techniques=["T0807"],
    )
    ics_batch = MagicMock(tenant=_tenant(), rules=[ics_rule])
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [ics_batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        ElasticValidator().validate([ics_rule])
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"


def test_resolve_rule_sources_data_view_404_fails_rule_and_403_raises() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {"type": "query", "query": "process.name: *", "data_view_id": "missing-dv"}
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(404, json_data={"message": "Not found"})
        with pytest.raises(ElasticRuleCheckError, match="missing-dv"):
            resolve_rule_sources(client, block)

    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(403, text="Forbidden")
        with pytest.raises(ElasticTenantError, match="HTTP 403"):
            resolve_rule_sources(client, block)


def test_timestamp_fields_check_non_date_fails_and_missing_warns() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "query",
        "query": "process.name: *",
        "index": ["logs-*"],
        "overrides": {"timestamp": "event.ingested"},
    }
    # 1. Non-date type (keyword) fails with ElasticRuleCheckError
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={
                "indices": ["logs-2026.10"],
                "fields": {"event.ingested": {"keyword": {"type": "keyword", "searchable": True}}},
            },
        )
        with pytest.raises(ElasticRuleCheckError, match="not a date/date_nanos field"):
            run_timestamp_fields_check(client, block)

    # 2. Missing field in mappings emits a warning instead of failing
    warnings: list[str] = []
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={"indices": ["logs-2026.10"], "fields": {}},
        )
        run_timestamp_fields_check(client, block, warnings=warnings)
    assert any("event.ingested" in w for w in warnings)


def test_threat_match_fields_check_unonboarded_warns_and_non_searchable_fails() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "threat_match",
        "query": 'event.category : "file"',
        "index": ["logs-endpoint.events.file-*"],
        "threat": {
            "index": ["logs-ti_abusech.malware-*"],
            "query": 'threat.indicator.type : "file"',
            "mapping": [
                {
                    "entries": [
                        {
                            "field": "file.hash.sha256",
                            "value": "threat.indicator.file.hash.sha256",
                        }
                    ]
                }
            ],
        },
    }
    # 1. Unonboarded threat.index and missing event field warn without failing
    warnings: list[str] = []
    with patch.object(client.session, "get") as mock_get:
        mock_get.side_effect = [
            _mock_response(200, json_data={"indices": [], "fields": {}}),
            _mock_response(200, json_data={"indices": ["logs-endpoint-1"], "fields": {}}),
        ]
        run_threat_match_fields_check(client, block, warnings=warnings)
    assert len(warnings) == 2

    # 2. Non-searchable indicator field raises ElasticRuleCheckError
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={
                "indices": ["logs-ti-1"],
                "fields": {
                    "threat.indicator.file.hash.sha256": {
                        "binary": {"type": "binary", "searchable": False}
                    }
                },
            },
        )
        with pytest.raises(ElasticRuleCheckError, match="not searchable"):
            run_threat_match_fields_check(client, block)


def test_aggregation_field_check_non_200_fails_closed() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "query",
        "query": "process.name: *",
        "index": ["logs-*"],
        "suppression": {"group_by": ["host.name"]},
    }
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(503, text="unavailable")
        with pytest.raises(ElasticRuleCheckError, match="HTTP 503"):
            run_aggregation_fields_check(client, block)


_SEQUENCE = (
    "sequence by host.id with maxspan={maxspan}\n"
    '  [process where event.type == "start"]\n'
    '  [network where event.type == "start"]'
)


@pytest.fixture
def advisory_log(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, object]]]:
    """Warnings the validator and the ATT&CK mapper log, as ``(event, fields)``.

    Recorded at the loggers: loggers cached on first use bypass ``capture_logs``.
    """
    events: list[tuple[str, dict[str, object]]] = []

    class _Recorder:
        def warning(self, event: str, **fields: object) -> None:
            events.append((event, fields))

    monkeypatch.setattr(elastic_validator, "logger", _Recorder())
    monkeypatch.setattr(elastic_attack, "logger", _Recorder())
    _clear_validation_flags(monkeypatch)
    return events


def _advisory_codes(events: list[tuple[str, dict[str, object]]]) -> list[str]:
    return [str(fields["code"]) for _, fields in events if "code" in fields]


@pytest.mark.parametrize(
    ("rule_kwargs", "expected"),
    [
        pytest.param({"lookback": "0m"}, ["lookback_zero"], id="lookback-zero"),
        pytest.param({"lookback": "2h"}, ["lookback_long"], id="lookback-long"),
        pytest.param(
            {
                "rule_type": "threshold",
                "lookback": "10m",
                "threshold": {"field": ["user.name"], "value": 5},
            },
            ["threshold_lookback"],
            id="threshold-lookback-over-interval",
        ),
        pytest.param(
            {
                "rule_type": "threshold",
                "lookback": "2h",
                "threshold": {"field": ["user.name"], "value": 5},
            },
            ["lookback_long", "threshold_lookback"],
            id="threshold-lookback-is-independent-of-lookback-long",
        ),
        pytest.param(
            {
                "rule_type": "threshold",
                "lookback": "0m",
                "threshold": {"field": ["user.name"], "value": 5},
            },
            ["lookback_zero"],
            id="threshold-with-zero-lookback",
        ),
        pytest.param(
            {"rule_type": "esql", "query": "FROM logs-* | WHERE x", "lookback": "1m"},
            ["esql_metadata_id"],
            id="esql-metadata-id",
        ),
        pytest.param({"alert_severity": "High", "risk": 20}, ["risk_band"], id="risk-outside-band"),
        pytest.param(
            {
                "rule_type": "eql",
                "query": _SEQUENCE.format(maxspan="15m"),
                "interval": "5m",
                "lookback": "1m",
            },
            ["eql_maxspan_window"],
            id="eql-maxspan-over-window",
        ),
        pytest.param(
            {
                "rule_type": "eql",
                "query": _SEQUENCE.format(maxspan="3m"),
                "interval": "5m",
                "lookback": "1m",
            },
            ["eql_maxspan_lookback"],
            id="eql-maxspan-over-lookback-only",
        ),
        pytest.param(
            {
                "rule_type": "eql",
                "query": _SEQUENCE.format(maxspan="1m"),
                "interval": "5m",
                "lookback": "1m",
            },
            [],
            id="eql-maxspan-within-lookback",
        ),
        pytest.param({"lookback": "5m"}, [], id="nothing-to-advise"),
    ],
)
@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_emits_the_spec_advisory_codes(
    _mock_checks,
    advisory_log: list[tuple[str, dict[str, object]]],
    rule_kwargs: dict,
    expected: list[str],
) -> None:
    _run_validator(
        _elastic_rule("Advisory Codes", "00000000-0000-4000-8003-000000000030", **rule_kwargs)
    )
    assert _advisory_codes(advisory_log) == expected
    assert (os.environ.get("VALIDATION_WARNING_RAISED") == "1") is bool(expected)


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_logs_the_code_as_the_event_with_the_old_name_as_legacy_event(
    _mock_checks, advisory_log: list[tuple[str, dict[str, object]]]
) -> None:
    _run_validator(
        _elastic_rule("Legacy Event", "00000000-0000-4000-8003-000000000031", lookback="2h")
    )
    [(event, fields)] = advisory_log
    assert event == "lookback_long"
    assert fields["code"] == "lookback_long"
    assert fields["legacy_event"] == "elastic_lookback_long_warning"
    assert fields["rule"] == "Legacy Event"


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_logs_technique_not_enterprise_for_an_ics_technique(
    _mock_checks, advisory_log: list[tuple[str, dict[str, object]]]
) -> None:
    _run_validator(
        _elastic_rule(
            "ICS Technique",
            "00000000-0000-4000-8003-000000000032",
            lookback="5m",
            techniques=["T0807", "T1105"],
        )
    )
    [(event, fields)] = advisory_log
    assert event == "technique_not_enterprise"
    assert fields["technique"] == "T0807"
    assert fields["legacy_event"] == "skipping_non_enterprise_technique"
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"


def test_every_advisory_code_names_the_event_it_replaced() -> None:
    codes = {
        value
        for name, value in vars(elastic_advisories).items()
        if name.isupper() and name != "LEGACY_EVENTS"
    }
    assert codes == set(elastic_advisories.LEGACY_EVENTS)
    assert codes == {
        "lookback_zero",
        "lookback_long",
        "threshold_lookback",
        "esql_metadata_id",
        "eql_maxspan_window",
        "eql_maxspan_lookback",
        "risk_band",
        "technique_not_enterprise",
    }
