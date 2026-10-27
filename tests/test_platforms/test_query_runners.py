"""Each platform's ``opentide query`` runner against stand-in vendor answers.

No test reaches a network: the vendor client each runner builds is replaced,
and the stand-in records what the runner sent, so a test checks both the
request (window, limit, query as sent) and how the answer becomes rows.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from opentide.models.system_config import ConfigurationModels as C
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow

WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)


def _request(platform: str, text: str, **kwargs: Any) -> QueryRequest:
    return QueryRequest(platform=platform, text=text, window=WINDOW, **kwargs)


@dataclass
class FakeResponse:
    status_code: int = 200
    body: Any = field(default_factory=dict)

    def json(self) -> Any:
        if isinstance(self.body, (dict, list)):
            return self.body
        raise ValueError("not JSON")

    @property
    def text(self) -> str:
        return self.body if isinstance(self.body, str) else json.dumps(self.body)


@dataclass
class FakeSession:
    """Answers each call with the next queued response and records it."""

    responses: list[FakeResponse] = field(default_factory=list)
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)

    def _answer(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        return self._answer("POST", url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return self._answer("GET", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> FakeResponse:
        return self._answer("DELETE", url, **kwargs)


# --------------------------------------------------------------------------
# Sentinel
# --------------------------------------------------------------------------


def _sentinel_tenant() -> C.Systems.Sentinel.Tenant:
    setup = C.Systems.Sentinel.Tenant.Setup(
        ssl=True,
        resource_group="rg",
        workspace_name="soc",
        workspace_id="ws-1",
        azure_tenant_id="t",
        azure_subscription_id="s",
        azure_client_id="c",
        azure_client_secret="secret",
    )
    return C.Systems.Sentinel.Tenant(name="soc-prod", description="", setup=setup)


@dataclass
class FakeTable:
    columns: list[str]
    columns_types: list[str]
    rows: list[list[Any]]


@pytest.fixture
def azure(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import azure.identity
    import azure.monitor.query as monitor

    state: dict[str, Any] = {"response": None, "calls": []}

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            state["client"] = kwargs

        def query_workspace(self, **kwargs: Any) -> Any:
            state["calls"].append(kwargs)
            response = state["response"]
            if isinstance(response, Exception):
                raise response
            return response

    monkeypatch.setattr(monitor, "LogsQueryClient", Client)
    monkeypatch.setattr(azure.identity, "ClientSecretCredential", lambda *a, **k: "credential")
    return state


def test_sentinel_sends_the_window_and_one_row_past_the_limit(azure: dict[str, Any]) -> None:
    from azure.monitor.query import LogsQueryStatus

    from opentide.platforms.sentinel.runner import SentinelQueryRunner

    table = FakeTable(
        ["TimeGenerated", "Computer"],
        ["datetime", "string"],
        [[datetime(2026, 10, 27, tzinfo=timezone.utc), f"host-{n}"] for n in range(3)],
    )
    azure["response"] = type("R", (), {"status": LogsQueryStatus.SUCCESS, "tables": [table]})()
    result = SentinelQueryRunner().run(
        _request("sentinel", "SecurityEvent", limit=2), _sentinel_tenant()
    )
    (call,) = azure["calls"]
    assert call["workspace_id"] == "ws-1"
    assert call["timespan"] == (WINDOW.start, WINDOW.end)
    assert call["query"] == "SecurityEvent\n| take 3"
    assert [column.name for column in result.columns] == ["TimeGenerated", "Computer"]
    assert result.columns[1].type == "string"
    assert [row["Computer"] for row in result.rows] == ["host-0", "host-1"]
    assert result.truncated is True
    assert result.sent == "SecurityEvent\n| take 3"


def test_sentinel_keeps_a_query_that_already_takes_rows(azure: dict[str, Any]) -> None:
    from azure.monitor.query import LogsQueryStatus

    from opentide.platforms.sentinel.runner import SentinelQueryRunner

    azure["response"] = type("R", (), {"status": LogsQueryStatus.SUCCESS, "tables": []})()
    result = SentinelQueryRunner().run(
        _request("sentinel", "SecurityEvent | take 5 // five"), _sentinel_tenant()
    )
    assert azure["calls"][0]["query"] == "SecurityEvent | take 5 // five"
    assert result.rows == () and result.sent is None


def test_sentinel_reports_a_partial_result_as_partial(azure: dict[str, Any]) -> None:
    from azure.monitor.query import LogsQueryStatus

    from opentide.platforms.sentinel.runner import SentinelQueryRunner

    error = type("E", (), {"message": "query exceeded the row cap"})()
    azure["response"] = type(
        "R",
        (),
        {
            "status": LogsQueryStatus.PARTIAL,
            "partial_data": [FakeTable(["a"], ["int"], [[1]])],
            "partial_error": error,
        },
    )()
    result = SentinelQueryRunner().run(_request("sentinel", "T"), _sentinel_tenant())
    assert result.partial is True
    assert result.rows == ({"a": 1},)
    assert "row cap" in result.warnings[0]


def test_sentinel_refusal_carries_the_kql_parser_message(azure: dict[str, Any]) -> None:
    from azure.core.exceptions import HttpResponseError

    from opentide.platforms.sentinel.runner import SentinelQueryRunner

    error = HttpResponseError(message="BadArgumentError")
    error.error = type(
        "O", (), {"innererror": {"innererror": {"message": "Failed to resolve table 'Nope'"}}}
    )()
    azure["response"] = error
    with pytest.raises(QueryRefused) as refused:
        SentinelQueryRunner().run(_request("sentinel", "Nope"), _sentinel_tenant())
    assert refused.value.detail == "Failed to resolve table 'Nope'"


def test_sentinel_refuses_unset_credentials(azure: dict[str, Any]) -> None:
    from opentide.platforms.sentinel.runner import SentinelQueryRunner

    tenant = _sentinel_tenant()
    tenant.setup.azure_client_secret = "$AZURE_SECRET"
    with pytest.raises(ValueError, match="AZURE_SECRET"):
        SentinelQueryRunner().run(_request("sentinel", "T"), tenant)
    assert azure["calls"] == []


# --------------------------------------------------------------------------
# Defender
# --------------------------------------------------------------------------


def _defender_tenant() -> C.Systems.DefenderForEndpoint.Tenant:
    setup = C.Systems.DefenderForEndpoint.Tenant.Setup(
        ssl=True, tenant_id="t", client_id="c", client_secret="s"
    )
    return C.Systems.DefenderForEndpoint.Tenant(name="xdr", description="", setup=setup)


@pytest.fixture
def graph(monkeypatch: pytest.MonkeyPatch) -> FakeSession:
    import opentide.platforms.defender_for_endpoint.client as client

    session = FakeSession()

    class Service:
        HUNTING_QUERY_ENDPOINT = "https://graph.example/runHuntingQuery"

        def __init__(self, tenant: object) -> None:
            self.session = session

    monkeypatch.setattr(client, "DefenderForEndpointService", Service)
    return session


def test_defender_maps_schema_and_results(graph: FakeSession) -> None:
    from opentide.platforms.defender_for_endpoint.runner import DefenderQueryRunner

    graph.responses.append(
        FakeResponse(
            body={
                "schema": [{"name": "Timestamp", "type": "DateTime"}, {"name": "DeviceName"}],
                "results": [{"Timestamp": "t1", "DeviceName": "a"}],
            }
        )
    )
    result = DefenderQueryRunner().run(
        _request("defender_for_endpoint", "DeviceProcessEvents"), _defender_tenant()
    )
    _, url, kwargs = graph.calls[0]
    assert url.endswith("runHuntingQuery")
    assert kwargs["json"] == {
        "Query": "DeviceProcessEvents\n| take 101",
        "Timespan": "2026-10-26T08:00:00.000Z/2026-10-27T08:00:00.000Z",
    }
    assert [(c.name, c.type) for c in result.columns] == [
        ("Timestamp", "DateTime"),
        ("DeviceName", None),
    ]
    assert result.rows == ({"Timestamp": "t1", "DeviceName": "a"},)
    assert result.truncated is False


def test_defender_names_the_missing_permission_on_403(graph: FakeSession) -> None:
    from opentide.platforms.defender_for_endpoint.runner import DefenderQueryRunner

    graph.responses.append(FakeResponse(403, {"error": {"message": "Forbidden"}}))
    with pytest.raises(QueryRefused, match=r"ThreatHunting\.Read\.All") as refused:
        DefenderQueryRunner().run(_request("defender_for_endpoint", "T"), _defender_tenant())
    assert refused.value.detail == "Forbidden"


def test_defender_refuses_a_window_past_thirty_days(graph: FakeSession) -> None:
    from opentide.platforms.defender_for_endpoint.runner import DefenderQueryRunner

    wide = TimeWindow(datetime(2026, 1, 1, tzinfo=timezone.utc), WINDOW.end)
    request = QueryRequest(platform="defender_for_endpoint", text="T", window=wide)
    with pytest.raises(QueryRefused, match="30 days"):
        DefenderQueryRunner().run(request, _defender_tenant())
    assert graph.calls == []


# --------------------------------------------------------------------------
# Splunk
# --------------------------------------------------------------------------


def _splunk_tenant() -> C.Systems.Splunk.Tenant:
    setup = C.Systems.Splunk.Tenant.Setup(
        ssl=True, url="splunk.example", port=8089, app="search", token="tok"
    )
    return C.Systems.Splunk.Tenant(name="es", description="", setup=setup)


@pytest.fixture
def splunk(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import opentide.platforms.splunk.client as client

    state: dict[str, Any] = {"answer": b"{}", "calls": []}

    class Jobs:
        def oneshot(self, query: str, **params: Any) -> io.BytesIO:
            state["calls"].append((query, params))
            answer = state["answer"]
            if isinstance(answer, Exception):
                raise answer
            return io.BytesIO(answer)

    def connect(**kwargs: Any) -> Any:
        state["connect"] = kwargs
        return type("Service", (), {"jobs": Jobs()})()

    monkeypatch.setattr(client, "connect_splunk", connect)
    return state


def test_splunk_runs_a_oneshot_search_over_the_window(splunk: dict[str, Any]) -> None:
    from opentide.platforms.splunk.runner import SplunkQueryRunner

    splunk["answer"] = json.dumps(
        {
            "fields": [{"name": "_time"}, {"name": "host"}],
            "results": [{"_time": "1", "host": "a"}, {"_time": "2", "host": "b"}],
            "messages": [{"type": "WARN", "text": "index 'x' does not exist"}],
        }
    ).encode()
    result = SplunkQueryRunner().run(_request("splunk", "index=main", limit=1), _splunk_tenant())
    query, params = splunk["calls"][0]
    assert query == "search index=main"
    assert params == {
        "earliest_time": "2026-10-26T08:00:00.000Z",
        "latest_time": "2026-10-27T08:00:00.000Z",
        "count": 2,
        "output_mode": "json",
    }
    assert splunk["connect"]["app"] == "search"
    assert [c.name for c in result.columns] == ["_time", "host"]
    assert result.rows == ({"_time": "1", "host": "a"},)
    assert result.truncated is True
    assert result.warnings == ("index 'x' does not exist",)


def test_splunk_keeps_a_query_that_starts_with_a_command(splunk: dict[str, Any]) -> None:
    from opentide.platforms.splunk.runner import SplunkQueryRunner

    SplunkQueryRunner().run(_request("splunk", "| tstats count"), _splunk_tenant())
    assert splunk["calls"][0][0] == "| tstats count"


def test_splunk_refusal_carries_the_parser_message(splunk: dict[str, Any]) -> None:
    from splunklib.binding import HTTPError

    from opentide.platforms.splunk.runner import SplunkQueryRunner

    body = json.dumps({"messages": [{"type": "FATAL", "text": "Unknown search command 'foo'"}]})
    response = type(
        "Resp",
        (),
        {"status": 400, "reason": "Bad Request", "headers": [], "body": io.BytesIO(body.encode())},
    )()
    splunk["answer"] = HTTPError(response)
    with pytest.raises(QueryRefused) as refused:
        SplunkQueryRunner().run(_request("splunk", "| foo"), _splunk_tenant())
    assert refused.value.detail == "Unknown search command 'foo'"


# --------------------------------------------------------------------------
# SentinelOne
# --------------------------------------------------------------------------


def _s1_tenant() -> C.Systems.SentinelOne.Tenant:
    setup = C.Systems.SentinelOne.Tenant.Setup(
        ssl=True, url="https://s1.example", account_id=42, api_token="tok", site_id=7
    )
    return C.Systems.SentinelOne.Tenant(name="s1", description="", setup=setup)


@pytest.fixture
def s1(monkeypatch: pytest.MonkeyPatch) -> FakeSession:
    import opentide.platforms.sentinel_one.client as client
    import opentide.platforms.sentinel_one.runner as runner

    session = FakeSession()

    class Service:
        CREATE_QUERY_ENDPOINT = "https://s1.example/web/api/v2.1/dv/events/pq"

        def __init__(self, tenant: object) -> None:
            self.session = session

    monkeypatch.setattr(client, "SentinelOneService", Service)
    monkeypatch.setattr(runner, "sleep", lambda seconds: None)
    return session


def test_sentinel_one_polls_until_the_powerquery_finishes(s1: FakeSession) -> None:
    from opentide.platforms.sentinel_one.runner import SentinelOneQueryRunner

    s1.responses += [
        FakeResponse(body={"data": {"queryId": "q1", "status": "RUNNING"}}),
        FakeResponse(body={"data": {"queryId": "q1", "status": "RUNNING"}}),
        FakeResponse(
            body={
                "data": {
                    "queryId": "q1",
                    "status": "FINISHED",
                    "columns": [{"name": "src.process.name"}, {"name": "endpoint.name"}],
                    "data": [["cmd.exe", "ws-1"]],
                }
            }
        ),
    ]
    result = SentinelOneQueryRunner().run(
        _request("sentinel_one", 'event.type = "Process Creation"'), _s1_tenant()
    )
    method, url, kwargs = s1.calls[0]
    assert (method, url) == ("POST", "https://s1.example/web/api/v2.1/dv/events/pq")
    assert kwargs["json"] == {
        "query": 'event.type = "Process Creation" | limit 101',
        "fromDate": "2026-10-26T08:00:00.000Z",
        "toDate": "2026-10-27T08:00:00.000Z",
        "limit": 101,
        "accountIds": ["42"],
        "siteIds": ["7"],
    }
    assert [call[:2] for call in s1.calls[1:]] == [
        ("GET", "https://s1.example/web/api/v2.1/dv/events/pq-ping")
    ] * 2
    assert s1.calls[1][2]["params"] == {"queryId": "q1"}
    assert result.rows == ({"src.process.name": "cmd.exe", "endpoint.name": "ws-1"},)
    assert result.vendor_query_id == "q1"


def test_sentinel_one_gives_up_at_the_timeout(
    s1: FakeSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import opentide.platforms.sentinel_one.runner as runner

    clock = iter([0.0, 0.0, 999.0])
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(clock))
    s1.responses += [
        FakeResponse(body={"data": {"queryId": "q1", "status": "RUNNING"}}),
        FakeResponse(body={"data": {"queryId": "q1", "status": "RUNNING"}}),
    ]
    with pytest.raises(QueryRefused, match="did not finish within 5s"):
        runner.SentinelOneQueryRunner().run(_request("sentinel_one", "x", timeout=5), _s1_tenant())


def test_sentinel_one_refusal_carries_the_api_detail(s1: FakeSession) -> None:
    from opentide.platforms.sentinel_one.runner import SentinelOneQueryRunner

    s1.responses.append(FakeResponse(400, {"errors": [{"detail": "Syntax error at 3"}]}))
    with pytest.raises(QueryRefused) as refused:
        SentinelOneQueryRunner().run(_request("sentinel_one", "x |"), _s1_tenant())
    assert refused.value.detail == "Syntax error at 3"


# --------------------------------------------------------------------------
# Carbon Black Cloud
# --------------------------------------------------------------------------


def _cbc_tenant() -> C.Systems.CarbonBlackCloud.Tenant:
    setup = C.Systems.CarbonBlackCloud.Tenant.Setup(
        ssl=True, url="https://cbc.example", org_key="ORG", token="tok"
    )
    return C.Systems.CarbonBlackCloud.Tenant(name="cbc", description="", setup=setup)


@pytest.fixture
def cbc(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import opentide.platforms.carbon_black.client as client

    state: dict[str, Any] = {"found": [], "calls": []}

    class Query:
        def where(self, text: str) -> Query:
            state["calls"].append(("where", text))
            return self

        def set_time_range(self, **kwargs: Any) -> Query:
            state["calls"].append(("set_time_range", kwargs))
            return self

        def set_rows(self, rows: int) -> Query:
            state["calls"].append(("set_rows", rows))
            return self

        def timeout(self, msecs: int) -> None:
            state["calls"].append(("timeout", msecs))

        def __iter__(self) -> Iterator[Any]:
            found = state["found"]
            if isinstance(found, Exception):
                raise found
            return iter(found)

    class Service:
        def __init__(self, tenant: object) -> None:
            self.service = type("Api", (), {"select": staticmethod(lambda model: Query())})()

    monkeypatch.setattr(client, "CarbonBlackCloudService", Service)
    return state


def test_carbon_black_flattens_process_documents(cbc: dict[str, Any]) -> None:
    from opentide.platforms.carbon_black.runner import CarbonBlackQueryRunner

    process = type("P", (), {"_info": {"process_name": "cmd.exe", "device": {"name": "ws"}}})
    cbc["found"] = [process(), process()]
    result = CarbonBlackQueryRunner().run(
        _request("carbon_black_cloud", "process_name:cmd.exe", limit=1, timeout=30),
        _cbc_tenant(),
    )
    assert cbc["calls"] == [
        ("where", "process_name:cmd.exe"),
        (
            "set_time_range",
            {"start": "2026-10-26T08:00:00.000Z", "end": "2026-10-27T08:00:00.000Z"},
        ),
        ("set_rows", 2),
        ("timeout", 30000),
    ]
    assert result.rows == ({"process_name": "cmd.exe", "device.name": "ws"},)
    assert result.truncated is True


def test_carbon_black_syntax_error_is_a_refusal(cbc: dict[str, Any]) -> None:
    from cbc_sdk.errors import QuerySyntaxError

    from opentide.platforms.carbon_black.runner import CarbonBlackQueryRunner

    cbc["found"] = QuerySyntaxError("/search", message="unbalanced parenthesis")
    with pytest.raises(QueryRefused, match="refused the query") as refused:
        CarbonBlackQueryRunner().run(_request("carbon_black_cloud", "(x"), _cbc_tenant())
    assert "unbalanced parenthesis" in str(refused.value.detail)


# --------------------------------------------------------------------------
# CrowdStrike
# --------------------------------------------------------------------------


def _crowdstrike_tenant() -> C.Systems.Crowdstrike.Tenant:
    setup = C.Systems.Crowdstrike.Tenant.Setup(
        ssl=True, api="EU-1", client_id="c", client_secret="s", customer_id="cid"
    )
    return C.Systems.Crowdstrike.Tenant(name="falcon", description="", setup=setup)


@pytest.fixture
def falcon(monkeypatch: pytest.MonkeyPatch) -> FakeSession:
    import opentide.platforms.crowdstrike.client as client
    import opentide.platforms.crowdstrike.runner as runner

    session = FakeSession()

    class Service:
        def __init__(self, tenant: object) -> None:
            self.session = session

        def _get_base_api(self, domain: str) -> str:
            return "https://api.eu-1.crowdstrike.com"

    monkeypatch.setattr(client, "CrowdstrikeService", Service)
    monkeypatch.setattr(runner, "sleep", lambda seconds: None)
    return session


def test_crowdstrike_starts_and_polls_a_query_job(falcon: FakeSession) -> None:
    from opentide.platforms.crowdstrike.runner import CrowdstrikeQueryRunner

    falcon.responses += [
        FakeResponse(body={"id": "job-1"}),
        FakeResponse(body={"done": False}),
        FakeResponse(body={"done": True, "events": [{"ComputerName": "ws", "aid": {"x": 1}}]}),
    ]
    result = CrowdstrikeQueryRunner().run(
        _request("crowdstrike", "#event_simpleName=ProcessRollup2"), _crowdstrike_tenant()
    )
    method, url, kwargs = falcon.calls[0]
    jobs = "https://api.eu-1.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs"
    assert (method, url) == ("POST", jobs)
    assert kwargs["json"] == {
        "queryString": "#event_simpleName=ProcessRollup2\n| head(limit=101)",
        "start": int(WINDOW.start.timestamp() * 1000),
        "end": int(WINDOW.end.timestamp() * 1000),
        "isLive": False,
    }
    assert [call[:2] for call in falcon.calls[1:]] == [("GET", f"{jobs}/job-1")] * 2
    assert result.rows == ({"ComputerName": "ws", "aid.x": 1},)
    assert result.vendor_query_id == "job-1"


def test_crowdstrike_stops_the_job_it_stops_waiting_for(
    falcon: FakeSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import opentide.platforms.crowdstrike.runner as runner

    clock = iter([0.0, 999.0])
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(clock))
    falcon.responses += [
        FakeResponse(body={"id": "job-1"}),
        FakeResponse(body={"done": False}),
        FakeResponse(204, ""),
    ]
    with pytest.raises(QueryRefused, match="did not finish"):
        runner.CrowdstrikeQueryRunner().run(
            _request("crowdstrike", "x", index=("investigate_view",)), _crowdstrike_tenant()
        )
    method, url, _ = falcon.calls[-1]
    assert method == "DELETE"
    assert url.endswith("/repositories/investigate_view/queryjobs/job-1")


def test_crowdstrike_names_the_scope_on_403(falcon: FakeSession) -> None:
    from opentide.platforms.crowdstrike.runner import CrowdstrikeQueryRunner

    falcon.responses.append(FakeResponse(403, "denied"))
    with pytest.raises(QueryRefused) as refused:
        CrowdstrikeQueryRunner().run(_request("crowdstrike", "x"), _crowdstrike_tenant())
    assert refused.value.detail == "the API client needs the NGSIEM: Read scope"


# --------------------------------------------------------------------------
# HarfangLab
# --------------------------------------------------------------------------


def _harfanglab_tenant() -> C.Systems.HarfangLab.Tenant:
    setup = C.Systems.HarfangLab.Tenant.Setup(
        ssl=True, type="cloud", url="https://hl.example/", api_token="tok", source_id="src"
    )
    return C.Systems.HarfangLab.Tenant(name="hl", description="", setup=setup)


@pytest.fixture
def harfanglab(monkeypatch: pytest.MonkeyPatch) -> FakeSession:
    import opentide.platforms.harfanglab.client as client

    session = FakeSession()

    class Service:
        def __init__(self, tenant: object) -> None:
            self.session = session

    monkeypatch.setattr(client, "HarfangLabService", Service)
    return session


def test_harfanglab_filters_a_telemetry_source(harfanglab: FakeSession) -> None:
    from opentide.platforms.harfanglab.runner import HarfangLabQueryRunner

    harfanglab.responses.append(
        FakeResponse(
            body={"count": 5, "results": [{"process_name": "cmd.exe", "agent": {"hostname": "ws"}}]}
        )
    )
    result = HarfangLabQueryRunner().run(
        _request(
            "harfanglab", "processes process_name=cmd.exe 'commandline__icontains=a b'", limit=1
        ),
        _harfanglab_tenant(),
    )
    _, url, kwargs = harfanglab.calls[0]
    assert url == "https://hl.example/api/data/telemetry/Processes/"
    assert kwargs["params"] == {
        "process_name": "cmd.exe",
        "commandline__icontains": "a b",
        "@event_create_date__gte": "2026-10-26T08:00:00.000Z",
        "@event_create_date__lte": "2026-10-27T08:00:00.000Z",
        "ordering": "-@event_create_date",
        "limit": 2,
        "offset": 0,
    }
    assert result.rows == ({"process_name": "cmd.exe", "agent.hostname": "ws"},)
    assert result.truncated is True  # count says 5 matched


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("", "starts with a telemetry source"),
        ("registry key=x", "starts with a telemetry source"),
        ("processes cmd.exe", "is not a field=value filter"),
        ("processes limit=5", "is set from"),
    ],
)
def test_harfanglab_refuses_a_query_it_cannot_read(
    harfanglab: FakeSession, query: str, message: str
) -> None:
    from opentide.platforms.harfanglab.runner import HarfangLabQueryRunner

    with pytest.raises(QueryRefused, match=message):
        HarfangLabQueryRunner().run(_request("harfanglab", query), _harfanglab_tenant())
    assert harfanglab.calls == []


# --------------------------------------------------------------------------
# Elastic
# --------------------------------------------------------------------------


def _elastic_tenant(index: list[str] | None = None) -> C.Systems.Elastic.Tenant:
    setup = C.Systems.Elastic.Tenant.Setup(
        ssl=True,
        url="https://kibana.example",
        elasticsearch_url="https://es.example",
        api_key="key",
        space="soc",
        index=index,
    )
    return C.Systems.Elastic.Tenant(name="elastic", description="", setup=setup)


@pytest.fixture
def elastic(monkeypatch: pytest.MonkeyPatch) -> FakeSession:
    import opentide.platforms.elastic.runner as runner

    session = FakeSession()

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            self.session = session
            self.space = kwargs["space"]
            self.timeout = kwargs["timeout"]

        def _es_url(self, endpoint: str) -> str:
            return f"https://es.example{endpoint}"

        def preview_rule(self, payload: dict[str, Any], **kwargs: Any) -> FakeResponse:
            return session.post("preview", json=payload, **kwargs)

        def get_data_view_response(self, data_view_id: str) -> FakeResponse:
            return session.get(f"data_view/{data_view_id}")

    monkeypatch.setattr(runner, "ElasticClient", Client)
    return session


def test_elastic_esql_filters_the_window_and_limits(elastic: FakeSession) -> None:
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    elastic.responses.append(
        FakeResponse(
            body={
                "columns": [{"name": "host.name", "type": "keyword"}],
                "values": [["a"], ["b"]],
            }
        )
    )
    result = ElasticQueryRunner().run(
        _request("elastic", "FROM logs-* // no LIMIT here", limit=1), _elastic_tenant()
    )
    _, url, kwargs = elastic.calls[0]
    assert url == "https://es.example/_query"
    assert kwargs["json"]["query"] == "FROM logs-* // no LIMIT here\n| LIMIT 2"
    assert kwargs["json"]["filter"]["range"]["@timestamp"]["gte"] == "2026-10-26T08:00:00.000Z"
    assert result.rows == ({"host.name": "a"},)
    assert result.truncated is True and result.language == "esql"


def test_elastic_lucene_searches_the_tenant_index(elastic: FakeSession) -> None:
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    elastic.responses.append(
        FakeResponse(
            body={
                "hits": {
                    "total": {"value": 1},
                    "hits": [{"_index": "logs-1", "_source": {"process": {"name": "cmd.exe"}}}],
                }
            }
        )
    )
    result = ElasticQueryRunner().run(
        _request("elastic", "process.name:cmd.exe", language="lucene"),
        _elastic_tenant(index=["logs-*", "winlogbeat-*"]),
    )
    _, url, kwargs = elastic.calls[0]
    assert url == "https://es.example/logs-*,winlogbeat-*/_search"
    assert kwargs["json"]["size"] == 101
    assert kwargs["json"]["query"]["bool"]["must"] == [
        {"query_string": {"query": "process.name:cmd.exe"}}
    ]
    assert result.rows == ({"_index": "logs-1", "process.name": "cmd.exe"},)


def test_elastic_eql_returns_sequence_events(elastic: FakeSession) -> None:
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    elastic.responses.append(
        FakeResponse(
            body={
                "hits": {"sequences": [{"events": [{"_source": {"a": 1}}, {"_source": {"a": 2}}]}]}
            }
        )
    )
    result = ElasticQueryRunner().run(
        _request("elastic", "sequence [a] [b]", language="eql", index=("logs-*",)),
        _elastic_tenant(),
    )
    assert elastic.calls[0][1] == "https://es.example/logs-*/_eql/search"
    assert result.rows == ({"_sequence": 1, "a": 1}, {"_sequence": 1, "a": 2})


def test_elastic_kuery_previews_a_rule_and_reads_its_alerts(elastic: FakeSession) -> None:
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    elastic.responses += [
        FakeResponse(body={"previewId": "p-1", "logs": [], "isAborted": False}),
        FakeResponse(
            body={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "process": {"name": "powershell.exe"},
                                "kibana": {"alert": {"rule": {"uuid": "p-1"}}},
                            }
                        }
                    ]
                }
            }
        ),
    ]
    result = ElasticQueryRunner().run(
        _request("elastic", 'process.name: "powershell.exe"', language="kuery"),
        _elastic_tenant(index=["logs-*"]),
    )
    _, _, preview = elastic.calls[0]
    assert preview["json"]["language"] == "kuery"
    assert preview["json"]["index"] == ["logs-*"]
    assert preview["json"]["from"] == "now-86400s"
    assert preview["timeframe_end"] == "2026-10-27T08:00:00.000Z"
    _, url, search = elastic.calls[1]
    assert url == "https://es.example/.preview.alerts-security.alerts-soc/_search"
    assert search["json"]["query"] == {"term": {"kibana.alert.rule.uuid": "p-1"}}
    assert result.rows == ({"process.name": "powershell.exe"},)
    assert "preview" in result.warnings[0]


def test_elastic_kuery_preview_errors_are_a_refusal(elastic: FakeSession) -> None:
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    elastic.responses.append(
        FakeResponse(body={"previewId": "p", "logs": [{"errors": ["Expected AND but found ':'"]}]})
    )
    with pytest.raises(QueryRefused) as refused:
        ElasticQueryRunner().run(
            _request("elastic", "a::b", language="kuery"), _elastic_tenant(index=["logs-*"])
        )
    assert refused.value.detail == "Expected AND but found ':'"


def test_elastic_needs_an_index_for_lucene(elastic: FakeSession) -> None:
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    with pytest.raises(QueryRefused, match="no index"):
        ElasticQueryRunner().run(_request("elastic", "x", language="lucene"), _elastic_tenant())
    assert elastic.calls == []


def test_elastic_error_reason_comes_from_root_cause(elastic: FakeSession) -> None:
    from opentide.platforms.elastic.runner import ElasticQueryRunner

    elastic.responses.append(
        FakeResponse(400, {"error": {"root_cause": [{"reason": "Unknown index [nope]"}]}})
    )
    with pytest.raises(QueryRefused) as refused:
        ElasticQueryRunner().run(_request("elastic", "FROM nope"), _elastic_tenant())
    assert refused.value.detail == "Unknown index [nope]"


# --------------------------------------------------------------------------
# Every platform
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "platform",
    [
        "sentinel",
        "defender_for_endpoint",
        "splunk",
        "sentinel_one",
        "carbon_black_cloud",
        "crowdstrike",
        "harfanglab",
        "elastic",
    ],
)
def test_every_platform_loads_a_runner_whose_languages_match_the_service(platform: str) -> None:
    from opentide.query.runner import QUERY_PLATFORMS, load_runner
    from opentide.query.service import PLATFORM_LANGUAGES

    assert platform in QUERY_PLATFORMS
    assert load_runner(platform).languages == PLATFORM_LANGUAGES[platform]


def test_a_runner_refuses_another_platforms_tenant() -> None:
    from opentide.platforms.splunk.runner import SplunkQueryRunner

    with pytest.raises(TypeError, match="Splunk tenant"):
        SplunkQueryRunner().run(_request("splunk", "x"), _sentinel_tenant())
