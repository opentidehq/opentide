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

from opentide._models.system_config import ConfigurationModels as C
from opentide._models.system_config import SystemConfig
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


#: A Sentinel block validates only with these, and deploy loads only what validates.
_SENTINEL_REQUIRED: dict[str, Any] = {"scheduling": {"frequency": "1h"}, "alert": {}}


def _sentinel(uuid: str, name: str, query: str) -> Any:
    block = {"enabled": True, "status": "STAGING", "query": query, **_SENTINEL_REQUIRED}
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
                **_SENTINEL_REQUIRED,
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
        _UUID_A, "Splunk", {"splunk": {"enabled": True, "status": "STAGING", "query": "x"}}
    )

    report = _validate(SentinelStandIn(runner), [splunk_only])

    assert report.checks == []
    assert report.failed is False


# --------------------------------------------------------------------------
# A slow query fails its own check; only a run of them makes a tenant unreachable
# --------------------------------------------------------------------------


@dataclass
class FailingRunner(StandInRunner):
    """Raises ``errors[marker]`` for each query that contains *marker*."""

    errors: dict[str, BaseException] = field(default_factory=dict)

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        for marker, error in self.errors.items():
            if marker in request.text:
                self.requests.append(request)
                raise error
        return super().run(request, tenant)


def _numbered(count: int) -> list[Any]:
    uuids = [f"00000000-0000-4000-8003-{index:012d}" for index in range(1, count + 1)]
    return [_sentinel(uuid, f"Rule {i}", f"Table{i}") for i, uuid in enumerate(uuids, start=1)]


def test_a_query_that_times_out_fails_only_its_own_check() -> None:
    """The 0.20.1 report: one read timeout ended the run as "Cannot reach splunk tenant"."""
    import requests

    runner = FailingRunner(errors={"Table2": requests.ReadTimeout("The read operation timed out")})
    rules = _numbered(4)

    report = _validate(SentinelStandIn(runner), rules)

    assert [request.text for request in runner.requests] == [
        "Table1",
        "Table2",
        "Table3",
        "Table4",
    ]
    assert [check.ok for check in report.checks] == [True, False, True, True]
    assert report.failed is True
    [timed_out] = report.timed_out()
    assert timed_out.name == "Rule 2"
    assert timed_out.code == "query_check_timeout"
    assert timed_out.errors == (
        "no answer within the 120s check timeout (The read operation timed out). Raise it "
        "with --check-timeout or OPENTIDE_QUERY_CHECK_TIMEOUT, or make the query cheaper",
    )
    assert report.to_dict()["checks"][1]["code"] == "query_check_timeout"
    assert "code" not in report.to_dict()["checks"][0]


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("The read operation timed out"),
        pytest.param("urllib3_retries", id="read-timeout-after-retries"),
        pytest.param("azure", id="azure-service-response-timeout"),
        pytest.param("gateway", id="gateway-504-page"),
    ],
)
def test_every_shape_of_read_timeout_fails_only_its_check(error: object) -> None:
    import requests
    import urllib3.exceptions

    from opentide.platforms.transport import GatewayTimeoutError

    if error == "urllib3_retries":
        inner = urllib3.exceptions.ReadTimeoutError(None, "/x", "Read timed out.")
        error = requests.ConnectionError(urllib3.exceptions.MaxRetryError(None, "/x", inner))
    elif error == "azure":
        from azure.core.exceptions import ServiceResponseTimeoutError

        read = requests.ReadTimeout("Read timed out.")
        error = ServiceResponseTimeoutError(read, error=read)
    elif error == "gateway":
        error = GatewayTimeoutError("HTTP 504 Gateway Timeout", status=504)
    assert isinstance(error, BaseException)
    runner = FailingRunner(errors={"Table1": error})

    report = _validate(SentinelStandIn(runner), _numbered(2))

    assert [check.code for check in report.checks] == ["query_check_timeout", None]


def test_three_timeouts_in_a_row_make_the_tenant_unreachable() -> None:
    from opentide.platforms.transport import TenantUnreachableError

    runner = FailingRunner(errors={"Table": TimeoutError("timed out")})

    with pytest.raises(TenantUnreachableError) as caught:
        _validate(SentinelStandIn(runner), _numbered(5))

    # The fourth and fifth rules are not sent to a tenant that answered none of three.
    assert len(runner.requests) == 3
    assert caught.value.timeouts == 3
    assert caught.value.tenant == "soc"
    assert "3 queries in a row got no answer within the 120s check timeout" in str(caught.value)
    assert "(the last: timed out)" in str(caught.value)


def test_an_answer_between_timeouts_resets_the_count() -> None:
    error = TimeoutError("timed out")
    runner = FailingRunner(errors={"Table1": error, "Table2": error, "Table4": error})

    report = _validate(SentinelStandIn(runner), _numbered(5))

    assert [check.ok for check in report.checks] == [False, False, True, False, True]
    assert len(report.timed_out()) == 3


def test_a_search_past_its_deadline_is_a_timeout_that_the_tenant_answered() -> None:
    """An asynchronous search the tenant still runs is not a tenant that does not answer."""
    from opentide.query.models import QueryTimedOut

    timed_out = QueryTimedOut(
        "the PowerQuery did not finish within 120s on soc",
        timeout=120,
        detail="narrow the window or raise --timeout",
    )
    runner = FailingRunner(errors={"Table": timed_out})

    report = _validate(SentinelStandIn(runner), _numbered(4))

    assert [check.code for check in report.checks] == ["query_check_timeout"] * 4
    # `opentide query`'s --timeout is not this command's: the advice names --check-timeout.
    assert "--timeout" not in report.checks[0].errors[0].replace("--check-timeout", "")
    assert "the PowerQuery did not finish within 120s" in report.checks[0].errors[0]


@pytest.mark.parametrize(
    "error",
    [
        pytest.param("connect", id="requests-connect-timeout"),
        pytest.param("refused", id="requests-connection-refused"),
        pytest.param("urlopen", id="urlopen-connect-timeout"),
    ],
)
def test_a_tenant_that_does_not_take_the_connection_is_unreachable_at_once(error: str) -> None:
    from urllib.error import URLError

    import requests

    from opentide.platforms.transport import TenantUnreachableError

    raised: BaseException = {
        "connect": requests.ConnectTimeout("Connection to host timed out"),
        "refused": requests.ConnectionError("Connection refused"),
        "urlopen": URLError(TimeoutError("timed out")),
    }[error]
    runner = FailingRunner(errors={"Table1": raised})

    with pytest.raises(TenantUnreachableError) as caught:
        _validate(SentinelStandIn(runner), _numbered(3))

    assert caught.value.timeouts == 0
    assert len(runner.requests) == 1


def test_the_check_timeout_reaches_each_query(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = StandInRunner()
    monkeypatch.setenv("OPENTIDE_QUERY_CHECK_TIMEOUT", "45")
    rules = [_sentinel(_UUID_A, "Good", "SecurityEvent")]

    report = _validate(SentinelStandIn(runner), rules)
    with patch("opentide.deployment.TideDeployment") as deployment:
        deployment.return_value.rule_deployment = [
            MagicMock(tenant=_sentinel_tenant(), rules=rules)
        ]
        explicit = SentinelStandIn(runner).validate(rules, timeout=7.5)

    assert [request.timeout for request in runner.requests] == [45.0, 7.5]
    assert (report.timeout, explicit.timeout) == (45.0, 7.5)


@pytest.mark.parametrize(
    ("value", "seconds"),
    [(None, 120.0), ("30", 30.0), (" 2.5 ", 2.5), (60, 60.0)],
)
def test_check_timeout_takes_the_option_then_the_variable(
    monkeypatch: pytest.MonkeyPatch, value: str | int | None, seconds: float
) -> None:
    from opentide.query.check import check_timeout

    monkeypatch.delenv("OPENTIDE_QUERY_CHECK_TIMEOUT", raising=False)
    assert check_timeout(value) == seconds
    monkeypatch.setenv("OPENTIDE_QUERY_CHECK_TIMEOUT", "90")
    assert check_timeout(value) == (90.0 if value is None else seconds)


@pytest.mark.parametrize("value", ["0", "-5", "abc", "", "nan", "inf", "1e999"])
def test_check_timeout_refuses_what_is_not_a_positive_number(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    from opentide.query.check import check_timeout

    if value:
        with pytest.raises(ValueError, match="--check-timeout must be a positive number"):
            check_timeout(value)
    monkeypatch.setenv("OPENTIDE_QUERY_CHECK_TIMEOUT", value)
    if value.strip():
        with pytest.raises(ValueError, match="OPENTIDE_QUERY_CHECK_TIMEOUT must be a positive"):
            check_timeout()
    else:
        # An empty variable is unset.
        assert check_timeout() == 120.0


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
        def __init__(self, tenant: object, *, timeout: float) -> None:
            built.append((tenant, timeout))
            self.service = api

    monkeypatch.setattr(client, "CarbonBlackCloudService", Service)
    runner = CarbonBlackQueryRunner()
    tenant = _cbc_tenant()
    request = QueryRequest(
        platform="carbon_black_cloud", text="process_name:x", window=check_window()
    )

    if valid:
        assert runner.check(request, tenant) == LiveCheck()
        # One client per tenant serves every rule, with the check's timeout.
        runner.check(request, tenant)
        assert built == [(tenant, request.timeout)]
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


def test_elastic_preview_that_is_not_json_is_a_refusal_with_its_status() -> None:
    """A proxy's 200 page raised JSONDecodeError, which ended the whole run."""
    import requests

    from opentide.platforms.elastic.client import ElasticClient
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    response = requests.Response()
    response.status_code = 200
    response._content = b"<html><head><title>Sign in</title></head></html>"
    response.headers["Content-Type"] = "text/html"
    end = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    with (
        patch.object(ElasticClient, "preview_rule", return_value=response),
        pytest.raises(QueryRefused, match="not JSON") as refused,
    ):
        ElasticQueryRunner().preview_rule(_elastic_tenant(), {"type": "query"}, end=end)
    assert refused.value.detail == "HTTP 200 with an HTML page titled 'Sign in'"


def test_elastic_fails_a_rule_whose_check_times_out_and_checks_the_rest() -> None:
    """Elastic runs its own loop: a read timeout there ended the run as unreachable, too."""
    import requests

    from opentide.platforms.elastic.validator import ElasticValidator
    from opentide.platforms.transport import TenantUnreachableError

    tenant = _elastic_tenant()
    rules = [
        _rule(f"00000000-0000-4000-8003-00000000000{i}", f"Rule {i}", {"elastic": {}})
        for i in range(1, 5)
    ]
    timeout = requests.ReadTimeout("Read timed out. (read timeout=30)")
    outcomes: list[BaseException | None] = [None, timeout, None, None]
    seen: list[tuple[str, int]] = []

    def _check(self: object, rule: Any, client: Any, *_args: object) -> None:
        seen.append((rule.name, client.timeout))
        error = outcomes[len(seen) - 1]
        if error is not None:
            raise error

    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as deployment,
        patch.object(ElasticValidator, "_validate_rule", _check),
    ):
        deployment.return_value.rule_deployment = [MagicMock(tenant=tenant, rules=rules)]
        report = ElasticValidator().validate(rules, timeout=45)
        assert [name for name, _ in seen] == ["Rule 1", "Rule 2", "Rule 3", "Rule 4"]
        # The check timeout is the client's; it used to be Elastic's own 30s.
        assert {seconds for _, seconds in seen} == {45}
        [timed_out] = report.rejected()
        assert (timed_out.name, timed_out.code) == ("Rule 2", "query_check_timeout")
        assert report.timeout == 45

        seen.clear()
        outcomes[:] = [timeout] * 4
        with pytest.raises(TenantUnreachableError, match="3 queries in a row"):
            ElasticValidator().validate(rules, timeout=45)
        assert len(seen) == 3


@pytest.mark.parametrize("rules", [1, 2])
def test_a_tenant_that_answered_nothing_is_unreachable_after_its_batch(rules: int) -> None:
    """A stalled TLS handshake reaches requests as a read timeout (urllib3 2.x).

    With fewer queries than the streak, every check used to fail as a slow
    query, with advice to raise --check-timeout that could not help.
    """
    import requests

    from opentide.platforms.transport import TenantUnreachableError

    runner = FailingRunner(errors={"Table": requests.ReadTimeout("Read timed out.")})

    with pytest.raises(TenantUnreachableError) as caught:
        _validate(SentinelStandIn(runner), _numbered(rules))

    assert len(runner.requests) == rules
    assert caught.value.timeouts == rules
    assert "it answered no request" in str(caught.value)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param("requests", id="ambiguous-read-timeout-then-an-answer"),
        pytest.param(TimeoutError("The read operation timed out"), id="urllib-read-timeout"),
    ],
)
def test_a_slow_query_on_a_tenant_that_took_the_connection_fails_only_its_check(
    error: object,
) -> None:
    import requests

    if error == "requests":
        runner = FailingRunner(errors={"Table1": requests.ReadTimeout("Read timed out.")})
        expected = ["query_check_timeout", None]
        rules = 2
    else:
        runner = FailingRunner(errors={"Table1": error})
        expected = ["query_check_timeout"]
        rules = 1
    report = _validate(SentinelStandIn(runner), _numbered(rules))

    assert [check.code for check in report.checks] == expected
