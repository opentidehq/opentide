"""Sentinel deployer against the ARM alert-rules REST API (#545).

The deployer compiles the ARM request body itself and sends it with
``requests``. These tests push rules through the real client with a capturing
transport adapter, so the body asserted here is exactly what a deploy would
send to ARM. Nothing leaves the process.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
import yaml
from requests.adapters import BaseAdapter
from tests.corpus_support import TIDE_CORPUS_ROOT

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.rule import DetectionRule
from opentide.platforms.sentinel import deployer as deployer_module
from opentide.platforms.sentinel.client import (
    ALERT_RULES_API_VERSION,
    ARM_SCOPE,
    SentinelApiError,
    SentinelClient,
    alert_rule_as_flat_dict,
    duration_isoformat,
)
from opentide.platforms.sentinel.deployer import (
    SENTINEL_TACTIC_ALIASES,
    SENTINEL_TACTICS,
    SentinelDeploy,
    sentinel_tactic,
)

CORPUS_SENTINEL_RULE = TIDE_CORPUS_ROOT / "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
RULES_URL = (
    f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/resourceGroups/rg"
    "/providers/Microsoft.OperationalInsights/workspaces/ws"
    "/providers/Microsoft.SecurityInsights/alertRules"
)


class _FakeCredential:
    def __init__(self) -> None:
        self.scopes: list[str] = []

    def get_token(self, *scopes: str, **kwargs: Any) -> Any:
        self.scopes.extend(scopes)
        return SimpleNamespace(token="token-x", expires_on=9999999999)


class _CapturingAdapter(BaseAdapter):
    """Records each request and answers from a queue of (status, json) replies."""

    def __init__(self, *replies: tuple[int, Any]) -> None:
        super().__init__()
        self.requests: list[requests.PreparedRequest] = []
        self.replies = list(replies)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        self.requests.append(request)
        status, payload = self.replies.pop(0) if self.replies else (200, {})
        response = requests.Response()
        response.status_code = status
        response._content = b"" if payload is None else json.dumps(payload).encode()
        response.url = request.url or ""
        response.request = request
        return response

    def close(self) -> None:
        return None


def _client(*replies: tuple[int, Any]) -> tuple[SentinelClient, _CapturingAdapter, _FakeCredential]:
    credential = _FakeCredential()
    client = SentinelClient(credential, SUBSCRIPTION)
    adapter = _CapturingAdapter(*replies)
    client.alert_rules._session.mount("https://", adapter)
    return client, adapter, credential


_TENANT = SimpleNamespace(
    name="tenant-a",
    setup=SimpleNamespace(resource_group="rg", workspace_name="ws"),
)


def _sent_body(rule: DetectionRule) -> tuple[dict[str, Any], requests.PreparedRequest]:
    """Deploy *rule* through the real client and return the captured ARM body."""
    client, adapter, _ = _client((201, {}))
    SentinelDeploy().deploy_mdr(data=rule, service=client, tenant_config=_TENANT)  # type: ignore[arg-type]
    (request,) = adapter.requests
    assert request.method == "PUT"
    assert request.url == f"{RULES_URL}/{rule.metadata.uuid}?api-version={ALERT_RULES_API_VERSION}"
    assert request.headers["Authorization"] == "Bearer token-x"
    return json.loads(request.body or b"{}"), request


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


def test_dry_run_body_is_what_the_client_sends(tide_corpus_repo: Path) -> None:
    rule = _corpus_rule(alert=FULL_ALERT, grouping=FULL_GROUPING, entities=FULL_ENTITIES)
    body, _ = _sent_body(rule)

    compiled = SentinelDeploy().compile_deployment(service=None, data=rule, tenant="tenant-a")

    assert compiled == body


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


def test_alert_rule_as_flat_dict_reads_a_listed_rule_for_the_importer() -> None:
    """The importer reads snake_case keys from the rules ARM lists."""
    rule = {
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
    flat = alert_rule_as_flat_dict(rule)

    assert flat["kind"] == "Scheduled"
    assert flat["name"] == "rule-1"
    assert flat["display_name"] == "Listed rule"
    assert flat["trigger_operator"] == "GreaterThan"
    assert flat["incident_configuration"]["create_incident"] is True
    assert flat["custom_details"] == {"CommandLine": "ProcessCommandLine"}
    assert str(flat["last_modified_utc"]).startswith("2026-10-01")
    assert "properties" not in flat


@pytest.mark.parametrize("entities", [None, []])
def test_rule_without_entities_omits_entity_mappings(
    tide_corpus_repo: Path, entities: list[Any] | None
) -> None:
    """ARM rejects ``entityMappings: []`` (length 1-10), so it is never sent empty (#549)."""
    rule = _corpus_rule(entities=entities)
    assert not rule.configurations.sentinel.entities  # type: ignore[union-attr]

    body, _ = _sent_body(rule)

    assert "entityMappings" not in body["properties"]


@pytest.mark.parametrize(
    ("grouping", "field"),
    [
        (None, "configurations.sentinel.grouping is missing"),
        ({"event": "SingleAlert"}, "configurations.sentinel.grouping.alert is missing"),
        (
            {"event": "SingleAlert", "alert": {"enabled": True}},
            "configurations.sentinel.grouping.alert.grouping_lookback is missing",
        ),
    ],
)
def test_missing_grouping_fails_with_the_rule_and_field(
    tide_corpus_repo: Path, grouping: dict[str, Any] | None, field: str
) -> None:
    """Spec: deploy MUST fail when grouping or grouping.alert is missing (#549)."""
    from opentide.core.errors import Errors

    rule = _corpus_rule(grouping=grouping)

    with pytest.raises(Errors.TideMDRDataModelErrors) as excinfo:
        SentinelDeploy().compile_deployment(service=None, data=rule, tenant="tenant-a")

    message = str(excinfo.value)
    assert rule.metadata.uuid in message
    assert field in message


def test_full_rule_body_matches_the_sdk_era_request(tide_corpus_repo: Path) -> None:
    """Byte-for-byte the body azure-mgmt-securityinsight 2.0.0b4 sent for this rule.

    Captured from the 0.15.0 deployer before the SDK was dropped, so the move to
    the REST API changes nothing on the wire or in the dry-run preview.
    """
    rule = _corpus_rule(
        alert={**FULL_ALERT, "suppression": "PT2H30M"},
        grouping=FULL_GROUPING,
        scheduling={"frequency": "30m", "lookback": "2d"},
    )

    body, _ = _sent_body(rule)

    props = body["properties"]
    assert props["queryFrequency"] == "PT30M00S"
    assert props["queryPeriod"] == "P2D"
    assert props["suppressionEnabled"] is True
    assert props["suppressionDuration"] == "PT02H30M00S"
    assert props["incidentConfiguration"]["groupingConfiguration"] == {
        "enabled": True,
        "groupByEntities": ["Account", "Host"],
        "lookbackDuration": "PT05H00M00S",
        "matchingMethod": "Selected",
        "reopenClosedIncident": True,
    }
    assert sorted(props) == [
        "alertDetailsOverride",
        "customDetails",
        "description",
        "displayName",
        "enabled",
        "eventGroupingSettings",
        "incidentConfiguration",
        "query",
        "queryFrequency",
        "queryPeriod",
        "severity",
        "suppressionDuration",
        "suppressionEnabled",
        "tactics",
        "techniques",
    ]


@pytest.mark.parametrize(
    ("duration", "expected"),
    [
        (timedelta(hours=1), "PT01H00M00S"),
        (timedelta(minutes=30), "PT30M00S"),
        (timedelta(hours=1, minutes=10), "PT01H10M00S"),
        (timedelta(days=1), "P1D"),
        (timedelta(weeks=2), "P14D"),
        (timedelta(days=1, hours=2), "P1DT02H00M00S"),
        (timedelta(days=1, minutes=5), "P1DT00H05M00S"),
        (timedelta(seconds=45), "PT45S"),
        (timedelta(minutes=1, seconds=5), "PT01M05S"),
        (timedelta(0), "PT0S"),
    ],
)
def test_duration_isoformat_matches_the_sdk_serialiser(duration: timedelta, expected: str) -> None:
    assert duration_isoformat(duration) == expected


def test_delete_sends_a_delete_for_the_rule() -> None:
    client, adapter, credential = _client((204, None))

    client.alert_rules.delete(resource_group_name="rg", workspace_name="ws", rule_id="rule-1")

    (request,) = adapter.requests
    assert request.method == "DELETE"
    assert request.url == f"{RULES_URL}/rule-1?api-version={ALERT_RULES_API_VERSION}"
    assert credential.scopes == [ARM_SCOPE]


def test_list_follows_next_link() -> None:
    next_link = f"{RULES_URL}?api-version={ALERT_RULES_API_VERSION}&$skipToken=page2"
    client, adapter, _ = _client(
        (200, {"value": [{"name": "a"}], "nextLink": next_link}),
        (200, {"value": [{"name": "b"}]}),
    )

    rules = list(client.alert_rules.list(resource_group_name="rg", workspace_name="ws"))

    assert [rule["name"] for rule in rules] == ["a", "b"]
    first, second = adapter.requests
    assert first.url == f"{RULES_URL}?api-version={ALERT_RULES_API_VERSION}"
    # The nextLink already carries the api-version; it is not appended twice.
    assert second.url == next_link


def test_arm_error_raises_with_status_code_and_message(tide_corpus_repo: Path) -> None:
    rule = _corpus_rule()
    client, _, _ = _client((400, {"error": {"code": "BadRequest", "message": "Query is invalid"}}))

    with pytest.raises(SentinelApiError) as excinfo:
        SentinelDeploy().deploy_mdr(data=rule, service=client, tenant_config=_TENANT)  # type: ignore[arg-type]

    assert excinfo.value.status_code == 400
    assert excinfo.value.code == "BadRequest"
    assert "HTTP 400 BadRequest: Query is invalid" in str(excinfo.value)
    # The bearer token never ends up in the error text.
    assert "token-x" not in str(excinfo.value)


def test_names_in_the_url_are_quoted() -> None:
    client, adapter, _ = _client((204, None))

    client.alert_rules.delete(
        resource_group_name="rg with space", workspace_name="ws/x", rule_id="rule-1"
    )

    (request,) = adapter.requests
    assert "/resourceGroups/rg%20with%20space/" in (request.url or "")
    assert "/workspaces/ws%2Fx/" in (request.url or "")


@pytest.mark.parametrize(
    ("stage", "tactic"),
    [
        ("Execution", "Execution"),
        ("Command and Control", "CommandAndControl"),
        ("Inhibit Response Function", "InhibitResponseFunction"),
        ("Defense Evasion", "DefenseEvasion"),
        # ATT&CK v19 split TA0005; Sentinel's AttackTactic enum predates it (#568).
        ("Stealth", "DefenseEvasion"),
        ("Defense Impairment", "DefenseEvasion"),
        # ICS names the tactic Evasion, which is not in the enum either.
        ("Evasion", "DefenseEvasion"),
        ("Not A Tactic", None),
    ],
)
def test_sentinel_tactic_maps_attack_stages_to_the_arm_enum(stage: str, tactic: str | None) -> None:
    assert sentinel_tactic(stage) == tactic


def test_every_mapped_tactic_is_in_the_arm_enum() -> None:
    assert set(SENTINEL_TACTIC_ALIASES.values()) <= SENTINEL_TACTICS


def test_new_attack_stages_are_sent_as_defense_evasion(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stealth, Defense Impairment and ICS Evasion techniques deploy as DefenseEvasion."""
    techniques = ["T1059", "T1027", "T1685.002", "T1562.001", "T0820"]
    monkeypatch.setattr(deployer_module, "techniques_resolver", lambda uuid: techniques)

    body, _ = _sent_body(_corpus_rule())

    assert body["properties"]["tactics"] == ["Execution", "DefenseEvasion"]
    assert body["properties"]["techniques"] == ["T1059", "T1027", "T1685", "T1562", "T0820"]


def test_stage_without_a_sentinel_tactic_is_dropped_with_a_warning(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(deployer_module, "techniques_resolver", lambda uuid: ["T1059"])
    monkeypatch.setattr(
        deployer_module,
        "get_vocab_entry",
        lambda vocab, identifier, field=None: ["Not A Tactic", "Execution"],
    )
    # Recorded at the deployer: loggers cached on first use bypass capture_logs.
    logger = MagicMock()
    monkeypatch.setattr(deployer_module, "logger", logger)

    compiled = SentinelDeploy().compile_deployment(
        service=None, data=_corpus_rule(), tenant="tenant-a"
    )

    assert compiled["properties"]["tactics"] == ["Execution"]
    logger.warning.assert_called_once_with(
        "dropping_attack_stage_without_sentinel_tactic", technique="T1059", stage="Not A Tactic"
    )
