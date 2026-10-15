"""Sentinel deployer against the locked azure-mgmt-securityinsight SDK (#545).

These tests compile real SDK models and push them through the client's own
``create_or_update`` pipeline with a capturing transport, so the body asserted
here is exactly what a deploy would send to ARM. Nothing leaves the process.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from tests.corpus_support import TIDE_CORPUS_ROOT

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.rule import DetectionRule
from opentide.platforms.sentinel.client import (
    alert_rule_as_flat_dict,
    alert_rule_request_body,
    securityinsights_client_class,
)
from opentide.platforms.sentinel.deployer import SentinelDeploy

pytest.importorskip("azure.mgmt.securityinsight")

from azure.core.credentials import AccessToken  # noqa: E402
from azure.core.pipeline.transport import HttpTransport  # noqa: E402

CORPUS_SENTINEL_RULE = TIDE_CORPUS_ROOT / "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"


class _FakeCredential:
    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        return AccessToken("x", 9999999999)


class _Captured(Exception):
    """Raised by the transport once the request is recorded, so nothing is sent."""


class _CapturingTransport(HttpTransport):
    def __init__(self) -> None:
        self.requests: list[Any] = []

    def __enter__(self) -> _CapturingTransport:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def send(self, request: Any, **kwargs: Any) -> Any:
        self.requests.append(request)
        raise _Captured


def _sent_body(rule: DetectionRule) -> tuple[dict[str, Any], Any]:
    """Deploy *rule* through the real client and return the captured ARM body."""
    transport = _CapturingTransport()
    client = securityinsights_client_class()(_FakeCredential(), SUBSCRIPTION, transport=transport)
    tenant = SimpleNamespace(
        name="tenant-a",
        setup=SimpleNamespace(resource_group="rg", workspace_name="ws"),
    )
    with pytest.raises(_Captured):
        SentinelDeploy().deploy_mdr(data=rule, service=client, tenant_config=tenant)  # type: ignore[arg-type]
    (request,) = transport.requests
    assert request.method == "PUT"
    assert f"/alertRules/{rule.metadata.uuid}?" in request.url
    body = request.content if hasattr(request, "content") else request.body
    return json.loads(body), request


def _corpus_rule(**sentinel_overrides: Any) -> DetectionRule:
    data = yaml.safe_load(CORPUS_SENTINEL_RULE.read_text(encoding="utf-8"))
    sentinel = data["configurations"]["sentinel"]
    for key, value in sentinel_overrides.items():
        if value is None:
            sentinel.pop(key, None)
        else:
            sentinel[key] = value
    return load_rule_from_dict(data)


FULL_ALERT = {
    "title": "Sentinel KQL Rule",
    "description": "Process {{ProcessName}} started",
    "severity": "Medium",
    "suppression": False,
    "create_incident": True,
    "dynamic_properties": [
        {"property": "ProductName", "column": "ProductName"},
        {"property": "ProductComponentName", "column": "ProductComponentName"},
        {"property": "Tactics", "column": "TacticsColumn"},
        {"property": "Severity", "column": "SeverityColumn"},
    ],
    "custom_details": [
        {"key": "CommandLine", "column": "ProcessCommandLine"},
        {"key": "parentProcess", "column": "ParentProcessName"},
    ],
}
FULL_GROUPING = {
    "event": "AlertPerResult",
    "alert": {
        "enabled": True,
        "grouping_lookback": "PT5H",
        "matching": "Selected",
        "group_by_entities": ["Account", "Host"],
        "reopen_closed_incidents": True,
    },
}
FULL_ENTITIES = [
    {"entity": "Account", "mappings": [{"identifier": "FullName", "column": "AccountUpn"}]},
    {
        "entity": "Host",
        "mappings": [
            {"identifier": "HostName", "column": "DeviceName"},
            {"identifier": "AzureID", "column": "DeviceId"},
        ],
    },
]


def test_deploy_compiles_and_serialises_a_full_rule(tide_corpus_repo: Path) -> None:
    rule = _corpus_rule(alert=FULL_ALERT, grouping=FULL_GROUPING, entities=FULL_ENTITIES)

    body, _ = _sent_body(rule)

    assert body["kind"] == "Scheduled"
    props = body["properties"]
    assert props["displayName"] == "Sentinel KQL Rule"
    assert props["enabled"] is True
    assert "SecurityEvent" in props["query"]
    assert props["severity"] == "Medium"
    assert props["suppressionEnabled"] is False
    assert props["tactics"] == ["Execution"]
    assert props["techniques"] == ["T1059"]
    override = props["alertDetailsOverride"]
    assert override["alertDisplayNameFormat"] == "Sentinel KQL Rule"
    assert override["alertDescriptionFormat"] == "Process {{ProcessName}} started"
    assert override["alertTacticsColumnName"] == "TacticsColumn"
    assert override["alertSeverityColumnName"] == "SeverityColumn"
    assert override["alertDynamicProperties"] == [
        {"alertProperty": "ProductName", "value": "ProductName"},
        {"alertProperty": "ProductComponentName", "value": "ProductComponentName"},
    ]
    # Custom-detail keys are user data: never case-converted.
    assert props["customDetails"] == {
        "CommandLine": "ProcessCommandLine",
        "parentProcess": "ParentProcessName",
    }
    assert props["eventGroupingSettings"] == {"aggregationKind": "AlertPerResult"}
    incident = props["incidentConfiguration"]
    assert incident["createIncident"] is True
    grouping = incident["groupingConfiguration"]
    assert grouping["enabled"] is True
    assert grouping["matchingMethod"] == "Selected"
    assert grouping["groupByEntities"] == ["Account", "Host"]
    assert grouping["reopenClosedIncident"] is True
    assert grouping["lookbackDuration"].startswith("PT")
    assert props["entityMappings"] == [
        {
            "entityType": "Account",
            "fieldMappings": [{"identifier": "FullName", "columnName": "AccountUpn"}],
        },
        {
            "entityType": "Host",
            "fieldMappings": [
                {"identifier": "HostName", "columnName": "DeviceName"},
                {"identifier": "AzureID", "columnName": "DeviceId"},
            ],
        },
    ]


def test_request_body_helper_matches_what_the_client_sends(tide_corpus_repo: Path) -> None:
    rule = _corpus_rule(alert=FULL_ALERT, grouping=FULL_GROUPING, entities=FULL_ENTITIES)
    body, _ = _sent_body(rule)

    compiled = SentinelDeploy().compile_deployment(service=None, data=rule, tenant="tenant-a")

    assert alert_rule_request_body(compiled) == body


def test_nrt_rule_is_sent_as_kind_nrt_without_schedule(tide_corpus_repo: Path) -> None:
    rule = _corpus_rule(
        scheduling={"nrt": True}, trigger={"operator": "GreaterThan", "threshold": 0}
    )

    body, _ = _sent_body(rule)

    assert body["kind"] == "NRT"
    for absent in ("queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold"):
        assert absent not in body["properties"]


def test_alert_rule_as_flat_dict_keeps_custom_detail_keys(tide_corpus_repo: Path) -> None:
    rule = _corpus_rule(alert=FULL_ALERT, grouping=FULL_GROUPING, entities=FULL_ENTITIES)
    compiled = SentinelDeploy().compile_deployment(service=None, data=rule, tenant="tenant-a")

    flat = alert_rule_as_flat_dict(compiled)

    assert flat["kind"] == "Scheduled"
    assert flat["display_name"] == "Sentinel KQL Rule"
    assert flat["custom_details"]["parentProcess"] == "ParentProcessName"
    assert flat["incident_configuration"]["grouping_configuration"]["matching_method"] == "Selected"
    assert flat["entity_mappings"][0]["field_mappings"][0]["column_name"] == "AccountUpn"


def test_client_class_accepts_either_sdk_spelling(monkeypatch: pytest.MonkeyPatch) -> None:
    import azure.mgmt.securityinsight as securityinsight

    class Legacy:
        pass

    class Renamed:
        pass

    monkeypatch.delattr(securityinsight, "SecurityInsightsMgmtClient", raising=False)
    monkeypatch.setattr(securityinsight, "SecurityInsights", Legacy, raising=False)
    assert securityinsights_client_class() is Legacy

    monkeypatch.setattr(securityinsight, "SecurityInsightsMgmtClient", Renamed, raising=False)
    assert securityinsights_client_class() is Renamed

    monkeypatch.delattr(securityinsight, "SecurityInsightsMgmtClient")
    monkeypatch.delattr(securityinsight, "SecurityInsights")
    with pytest.raises(ImportError, match="SecurityInsightsMgmtClient"):
        securityinsights_client_class()


def test_locked_sdk_has_every_model_the_deployer_uses() -> None:
    from azure.mgmt.securityinsight import models

    for name in (
        "ScheduledAlertRule",
        "AlertDetailsOverride",
        "AlertPropertyMapping",
        "EventGroupingSettings",
        "IncidentConfiguration",
        "GroupingConfiguration",
        "EntityMapping",
        "FieldMapping",
    ):
        assert hasattr(models, name), name


def test_alert_rule_as_flat_dict_reads_a_listed_rule_for_the_importer() -> None:
    """The importer reads snake_case keys from listed rules on either SDK generation."""
    from azure.mgmt.securityinsight import models

    response = {
        "id": "/subscriptions/x/alertRules/rule-1",
        "name": "rule-1",
        "kind": "Scheduled",
        "etag": "abc",
        "properties": {
            "displayName": "Listed rule",
            "description": "d",
            "enabled": True,
            "query": "SecurityEvent",
            "queryFrequency": "PT1H",
            "queryPeriod": "PT2H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionEnabled": False,
            "suppressionDuration": "PT1H",
            "severity": "High",
            "lastModifiedUtc": "2026-10-01T10:00:00Z",
            "customDetails": {"CommandLine": "ProcessCommandLine"},
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": False,
                    "lookbackDuration": "PT1H",
                    "matchingMethod": "AllEntities",
                },
            },
        },
    }
    if hasattr(models.ScheduledAlertRule, "deserialize"):
        rule = models.ScheduledAlertRule.deserialize(response)
    else:
        rule = models.ScheduledAlertRule(response)

    flat = alert_rule_as_flat_dict(rule)

    assert flat["kind"] == "Scheduled"
    assert flat["name"] == "rule-1"
    assert flat["display_name"] == "Listed rule"
    assert flat["trigger_operator"] == "GreaterThan"
    assert flat["incident_configuration"]["create_incident"] is True
    assert flat["custom_details"] == {"CommandLine": "ProcessCommandLine"}
    assert str(flat["last_modified_utc"]).startswith("2026-10-01")
    assert "properties" not in flat
