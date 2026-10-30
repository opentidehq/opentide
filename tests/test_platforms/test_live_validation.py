"""``validate query --live`` on the query runners: per-rule verdicts, as data (#673).

The live validator asks the platform's runner to ``check`` each query a deploy
sends, on each tenant it sends it to. These tests give it a stand-in runner and
read the report it returns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar
from unittest.mock import MagicMock, patch

import pytest

from opentide.models.system_config import ConfigurationModels as C
from opentide.models.system_config import SystemConfig
from opentide.platforms.live_validation import LiveQueryValidator, refusal_text
from opentide.query.check import CHECK_WINDOW, LiveCheckReport, RuleCheck, check_window
from opentide.query.models import (
    LiveCheck,
    QueryColumn,
    QueryRefused,
    QueryRequest,
    QueryResult,
    TimeWindow,
)
from opentide.query.runner import QueryRunner

_UUID_A = "00000000-0000-4000-8003-0000000000a1"
_UUID_B = "00000000-0000-4000-8003-0000000000b2"


def _rule(uuid: str, name: str, configurations: dict[str, Any]) -> Any:
    from opentide.loading.rule_loader import load_rule_from_dict

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
            "description": "d",
            "techniques": [],
            "response": {"alert_severity": "High"},
            "configurations": configurations,
        }
    )


def _sentinel(uuid: str, name: str, query: str) -> Any:
    block = {"enabled": True, "status": "STAGING", "query": query}
    return _rule(uuid, name, {"sentinel": block})


def _sentinel_tenant(name: str = "soc") -> C.Systems.Sentinel.Tenant:
    setup = C.Systems.Sentinel.Tenant.Setup(
        ssl=True,
        resource_group="rg",
        workspace_name="ws",
        workspace_id="ws-1",
        azure_tenant_id="t",
        azure_subscription_id="s",
        azure_client_id="c",
        azure_client_secret="secret",
    )
    return C.Systems.Sentinel.Tenant(name=name, description="", setup=setup)


@dataclass
class StandInRunner(QueryRunner):
    """Refuses the queries named in ``refuse``; records every check."""

    languages: ClassVar[tuple[str, ...]] = ("kql",)
    refuse: dict[str, QueryRefused] = field(default_factory=dict)
    columns: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    requests: list[QueryRequest] = field(default_factory=list)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        self.requests.append(request)
        for marker, refusal in self.refuse.items():
            if marker in request.text:
                raise refusal
        return QueryResult(columns=tuple(QueryColumn(name) for name in self.columns), rows=())

    def check(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> LiveCheck:
        found = super().check(request, tenant)
        return LiveCheck(result=found.result, warnings=self.warnings)


class SentinelStandIn(LiveQueryValidator):
    platform: ClassVar[str] = "sentinel"


def _validate(
    validator: LiveQueryValidator, rules: list[Any], *tenants: SystemConfig.Tenant
) -> LiveCheckReport:
    batches = [MagicMock(tenant=tenant, rules=rules) for tenant in tenants or (_sentinel_tenant(),)]
    with patch("opentide.deployment.TideDeployment") as deployment:
        deployment.return_value.rule_deployment = batches
        return validator.validate(rules)


def test_every_rule_is_checked_and_a_refusal_fails_only_its_rule() -> None:
    runner = StandInRunner(refuse={"Nope": QueryRefused("refused", detail="no table 'Nope'")})
    good = _sentinel(_UUID_A, "Good", "SecurityEvent")
    bad = _sentinel(_UUID_B, "Bad", "Nope")

    report = _validate(SentinelStandIn(runner), [bad, good])

    assert report.failed is True
    assert report.warned is False
    assert report.checks == [
        RuleCheck(rule=_UUID_B, name="Bad", tenant="soc", errors=("refused: no table 'Nope'",)),
        RuleCheck(rule=_UUID_A, name="Good", tenant="soc"),
    ]
    assert [check.ok for check in report.checks] == [False, True]
    assert report.to_dict()["checks"][0] == {
        "rule": _UUID_B,
        "name": "Bad",
        "tenant": "soc",
        "status": "failed",
        "errors": ["refused: no table 'Nope'"],
        "warnings": [],
    }


def test_each_query_is_a_one_row_search_over_the_last_minute() -> None:
    runner = StandInRunner()

    _validate(SentinelStandIn(runner), [_sentinel(_UUID_A, "Good", "SecurityEvent")])

    [request] = runner.requests
    assert request.limit == 1
    assert request.window.end - request.window.start == CHECK_WINDOW
    assert request.platform == "sentinel"


def test_a_rule_is_checked_on_each_tenant_deploy_sends_it_to() -> None:
    runner = StandInRunner()

    report = _validate(
        SentinelStandIn(runner),
        [_sentinel(_UUID_A, "Good", "SecurityEvent")],
        _sentinel_tenant("preview"),
        _sentinel_tenant("release"),
    )

    assert [check.tenant for check in report.checks] == ["preview", "release"]


def test_the_tenant_exclusions_deploy_compiles_are_in_the_checked_query() -> None:
    runner = StandInRunner()
    rule = _rule(
        _UUID_A,
        "Excluding",
        {
            "sentinel": {
                "enabled": True,
                "status": "STAGING",
                "query": "SecurityEvent",
                "exclusions": [
                    {"tenant": "soc", "query": "| where Account != 'svc'", "reason": "r"}
                ],
            }
        },
    )

    _validate(SentinelStandIn(runner), [rule])

    [request] = runner.requests
    assert "svc" in request.text


def test_runner_warnings_are_the_rules_warnings() -> None:
    runner = StandInRunner(warnings=("parser timed out",))

    report = _validate(SentinelStandIn(runner), [_sentinel(_UUID_A, "Slow", "SecurityEvent")])

    assert report.failed is False
    assert report.warned is True
    assert report.checks[0].warnings == ("parser timed out",)


def test_a_rule_with_no_query_to_send_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.query import rules

    def _none(rule: object, platform: str) -> list[object]:
        raise rules.RuleQueryError("rule 'Empty' has an empty sentinel query")

    monkeypatch.setattr(rules, "rule_queries", _none)
    runner = StandInRunner()

    report = _validate(SentinelStandIn(runner), [_sentinel(_UUID_A, "Empty", "SecurityEvent")])

    assert report.failed is True
    assert report.checks[0].errors == ("rule 'Empty' has an empty sentinel query",)
    assert runner.requests == []


def test_a_rule_without_the_platforms_block_is_skipped() -> None:
    runner = StandInRunner()
    splunk_only = _rule(
        _UUID_A, "Splunk", {"splunk": {"enabled": True, "status": "STAGING", "search": "x"}}
    )

    report = _validate(SentinelStandIn(runner), [splunk_only])

    assert report.checks == []
    assert report.failed is False


def test_an_error_that_is_not_a_refusal_reaches_the_caller() -> None:
    """A broken SDK or a refused credential is the run's failure, reported once by the CLI."""

    class Broken(StandInRunner):
        def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
            raise ModuleNotFoundError("azure")

    with pytest.raises(ModuleNotFoundError):
        _validate(SentinelStandIn(Broken()), [_sentinel(_UUID_A, "Good", "SecurityEvent")])


def test_a_validator_loads_its_platforms_runner() -> None:
    from opentide.platforms.sentinel.runner import SentinelQueryRunner
    from opentide.platforms.sentinel.validator import declare

    assert isinstance(declare().runner, SentinelQueryRunner)


def test_refusal_text_adds_the_vendor_detail() -> None:
    assert refusal_text(QueryRefused("refused")) == "refused"
    assert refusal_text(QueryRefused("refused", detail="why")) == "refused: why"


def test_check_window_ends_now() -> None:
    now = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    assert check_window(now) == TimeWindow(now - CHECK_WINDOW, now)


# --------------------------------------------------------------------------
# Defender: the required columns, on top of the search's answer
# --------------------------------------------------------------------------


def _defender(query: str) -> Any:
    block = {
        "enabled": True,
        "status": "STAGING",
        "query": query,
        "scheduling": "1H",
        "alert": {"category": "Execution"},
        "impacted_entities": {"device": "device_id"},
        "scope": {"selection": "All"},
    }
    return _rule(_UUID_A, "Defender", {"defender_for_endpoint": block})


def _defender_tenant() -> C.Systems.DefenderForEndpoint.Tenant:
    setup = C.Systems.DefenderForEndpoint.Tenant.Setup(
        ssl=True, tenant_id="t", client_id="c", client_secret="s"
    )
    return C.Systems.DefenderForEndpoint.Tenant(name="xdr", description="", setup=setup)


@pytest.mark.parametrize(
    ("columns", "errors"),
    [
        (("Timestamp", "DeviceId", "ReportId"), ()),
        (("Timestamp", "DeviceId"), ("the query's output lacks ReportId",)),
    ],
)
def test_defender_fails_a_query_without_the_custom_detection_columns(
    columns: tuple[str, ...], errors: tuple[str, ...]
) -> None:
    from opentide.platforms.defender_for_endpoint.validator import (
        DefenderForEndpointQueryValidator,
    )

    runner = StandInRunner(columns=columns)
    report = _validate(
        DefenderForEndpointQueryValidator(runner),
        [_defender("DeviceProcessEvents")],
        _defender_tenant(),
    )

    assert report.checks[0].errors == errors


# --------------------------------------------------------------------------
# Runners: the default check, and the parse-only checks
# --------------------------------------------------------------------------


def test_the_default_check_searches_for_one_row() -> None:
    runner = StandInRunner(columns=("a",))
    request = QueryRequest(platform="sentinel", text="T", window=check_window(), limit=50)

    found = runner.check(request, _sentinel_tenant())

    assert runner.requests[0].limit == 1
    assert found.result is not None
    assert found.result.columns == (QueryColumn("a"),)


def _cbc_tenant() -> C.Systems.CarbonBlackCloud.Tenant:
    setup = C.Systems.CarbonBlackCloud.Tenant.Setup(
        ssl=True, url="https://cbc.example", org_key="ORG", token="tok"
    )
    return C.Systems.CarbonBlackCloud.Tenant(name="cbc", description="", setup=setup)


@pytest.mark.parametrize("valid", [True, False])
def test_carbon_black_checks_with_search_validation_and_runs_no_search(
    monkeypatch: pytest.MonkeyPatch, valid: bool
) -> None:
    import opentide.platforms.carbon_black.client as client
    from opentide.platforms.carbon_black.runner import CarbonBlackQueryRunner

    api = MagicMock()
    api.validate_process_query.return_value = valid
    built: list[object] = []

    class Service:
        def __init__(self, tenant: object) -> None:
            built.append(tenant)
            self.service = api

    monkeypatch.setattr(client, "CarbonBlackCloudService", Service)
    runner = CarbonBlackQueryRunner()
    tenant = _cbc_tenant()
    request = QueryRequest(
        platform="carbon_black_cloud", text="process_name:x", window=check_window()
    )

    if valid:
        assert runner.check(request, tenant) == LiveCheck()
        # One client per tenant serves every rule.
        runner.check(request, tenant)
        assert len(built) == 1
    else:
        with pytest.raises(QueryRefused, match="refused the query on cbc"):
            runner.check(request, tenant)
    api.select.assert_not_called()


def _elastic_tenant() -> C.Systems.Elastic.Tenant:
    setup = C.Systems.Elastic.Tenant.Setup(
        ssl=True,
        url="https://kibana.test",
        elasticsearch_url="https://es.test",
        api_key="key",
        space="default",
    )
    return C.Systems.Elastic.Tenant(name="staging", description="", setup=setup)


@pytest.mark.parametrize(
    ("status", "raised"),
    [(400, QueryRefused), (500, QueryRefused), (401, "TenantConnectionError")],
)
def test_elastic_preview_rule_maps_kibanas_answer(status: int, raised: object) -> None:
    import requests

    from opentide.core.errors import Errors
    from opentide.platforms.elastic.client import ElasticClient
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    response = requests.Response()
    response.status_code = status
    response._content = b"nope"
    expected = Errors.TenantConnectionError if raised == "TenantConnectionError" else raised
    end = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    with (
        patch.object(ElasticClient, "preview_rule", return_value=response) as preview,
        pytest.raises(expected),  # type: ignore[arg-type]
    ):
        ElasticQueryRunner().preview_rule(_elastic_tenant(), {"type": "query"}, end=end)
    assert preview.call_args.kwargs == {
        "invocation_count": 1,
        "timeframe_end": "2026-10-30T12:00:00.000Z",
    }


def test_elastic_preview_rule_returns_the_preview() -> None:
    import json

    import requests

    from opentide.platforms.elastic.client import ElasticClient
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({"logs": [], "previewId": "p"}).encode()
    end = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    with patch.object(ElasticClient, "preview_rule", return_value=response):
        body = ElasticQueryRunner().preview_rule(_elastic_tenant(), {"type": "query"}, end=end)
    assert body == {"logs": [], "previewId": "p"}
