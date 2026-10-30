"""The ``validate query --live`` contract, pinned per platform (#673).

Each platform's live check runs here against a stand-in for the vendor API, at
the layer the check talks to (the Azure SDK client, the Graph and SentinelOne
HTTP sessions, a local Splunk, the Carbon Black SDK call, Kibana's rule
preview). A test pins what the command prints and exits with when the tenant
accepts the queries, refuses them, or warns: the ``--json`` document, the
human output and the exit code. The SDK's ``DetectionRule.validate_query``
answers are pinned beside them. Nothing here may read or leave a process-wide
environment flag.
"""

from __future__ import annotations

import json
import os
import types
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    clear_runtime_caches,
    materialise_corpus,
)
from tests.splunk_support import SplunkStandIn, serve_splunk
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()

_ENVIRONMENT = ("CI", "GITHUB_ACTIONS", "TF_BUILD", "DEPLOYMENT_PLAN")
_PROXIES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "OPENTIDE_PROXY")
_FLAGS = ("VALIDATION_ERROR_RAISED", "VALIDATION_WARNING_RAISED")
_RULES = Path("Objects/Detection Rules")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    repo = materialise_corpus(tmp_path / "corpus")
    for name in _ENVIRONMENT + _PROXIES + tuple(name.lower() for name in _PROXIES) + _FLAGS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    clear_runtime_caches()
    yield repo
    clear_runtime_caches()


@pytest.fixture(autouse=True)
def _flags_stay_unset() -> Iterator[None]:
    """No live check, passing or failing, sets a process-wide flag (#673).

    Set up before ``repo``, so the check runs after the test's own environment
    changes are undone.
    """
    yield
    _no_flags()


def _add_tenant(repo: Path, platform: str, setup: str, name: str = "soc") -> None:
    config = repo / ".opentide/configurations/systems" / f"{platform}.toml"
    tenant = f'\n[[tenants]]\nname = "{name}"\n[tenants.setup]\n{setup}'
    config.write_text(config.read_text(encoding="utf-8") + tenant, encoding="utf-8")


def _edit_rule(repo: Path, file: str, old: str, new: str) -> None:
    path = repo / _RULES / file
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _validate_json(platform: str, *args: str) -> tuple[int, dict[str, Any]]:
    result = runner.invoke(
        app, ["--json", "validate", "query", "--platform", platform, "--live", *args]
    )
    assert "Traceback" not in result.stderr
    payload = json.loads(result.stdout)
    # The one value that changes from run to run.
    duration_ms = payload.pop("duration_ms")
    assert isinstance(duration_ms, int)
    return result.exit_code, payload


def _validate_text(platform: str, *args: str) -> tuple[int, str]:
    result = runner.invoke(app, ["validate", "query", "--platform", platform, "--live", *args])
    assert "Traceback" not in result.output
    return result.exit_code, result.output


def _no_flags() -> None:
    for flag in _FLAGS:
        assert not os.environ.get(flag), f"{flag} leaked into the process environment"


def _failure(message: str) -> dict[str, Any]:
    return {
        "code": "command_failed",
        "message": message,
        "argument": None,
        "suggestion": None,
        "crash_log": None,
    }


def _checked(platform: str, queries: int, tenant: str) -> dict[str, Any]:
    return {
        "platform": platform,
        "mode": "live",
        "supported": True,
        "strategies": ["PREVIEW", "RELEASE"],
        "queries_validated": queries,
        "queries_per_tenant": {tenant: queries},
        "schema_version": 1,
        "command": "validate query",
        "summary": {"queries": queries, "tenants": 1},
        "next_actions": [],
    }


def _passed(platform: str, payload: dict[str, Any], *, queries: int, tenant: str = "soc") -> None:
    noun = "query" if queries == 1 else "queries"
    assert payload == {
        **_checked(platform, queries, tenant),
        "ok": True,
        "status": "passed",
        "message": f"{queries} {noun} valid on 1 tenant",
        "exit_code": 0,
        "failure": None,
    }


def _rejected(platform: str, payload: dict[str, Any], *, queries: int, tenant: str = "soc") -> None:
    message = f"Queries rejected on {platform} · {queries} checked on 1 tenant"
    assert payload == {
        **_checked(platform, queries, tenant),
        "ok": False,
        "status": "failed",
        "message": message,
        "error": message,
        "exit_code": 1,
        "failure": _failure(message),
    }


def _warned(platform: str, payload: dict[str, Any], *, queries: int, tenant: str = "soc") -> None:
    noun = "query" if queries == 1 else "queries"
    assert payload == {
        **_checked(platform, queries, tenant),
        "ok": True,
        "status": "passed",
        "message": f"{queries} {noun} valid on 1 tenant",
        "warnings": [f"Query validation reported warnings for {platform}"],
        "exit_code": 0,
        "failure": None,
    }


@dataclass
class FakeResponse:
    status_code: int = 200
    body: Any = field(default_factory=dict)

    def json(self) -> Any:
        return self.body

    @property
    def text(self) -> str:
        return json.dumps(self.body)

    @property
    def content(self) -> bytes:
        return self.text.encode("utf-8")


class FakeSession:
    """A ``TenantSession`` that answers every request with ``answer(method, url, kwargs)``."""

    def __init__(self, answer: Callable[[str, str, dict[str, Any]], FakeResponse]) -> None:
        self.headers: dict[str, str] = {}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self._answer = answer

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("POST", url, kwargs))
        return self._answer("POST", url, kwargs)

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("GET", url, kwargs))
        return self._answer("GET", url, kwargs)

    def delete(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("DELETE", url, kwargs))
        return self._answer("DELETE", url, kwargs)


# --------------------------------------------------------------------------
# Sentinel: the Azure Monitor client
# --------------------------------------------------------------------------

_SENTINEL_TENANT = """ssl = true
resource_group = "rg"
workspace_name = "soc"
workspace_id = "ws-1"
azure_tenant_id = "tenant-id"
azure_subscription_id = "subscription-id"
azure_client_id = "client-id"
azure_client_secret = "client-secret"
"""


@pytest.fixture
def azure(repo: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import azure.identity
    import azure.monitor.query as monitor
    from azure.monitor.query import LogsQueryStatus

    state: dict[str, Any] = {
        "answer": types.SimpleNamespace(status=LogsQueryStatus.SUCCESS, tables=[]),
        "queries": [],
    }

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def query_workspace(self, **kwargs: Any) -> Any:
            state["queries"].append(kwargs["query"])
            answer = state["answer"]
            if isinstance(answer, Exception):
                raise answer
            return answer

    monkeypatch.setattr(monitor, "LogsQueryClient", Client)
    monkeypatch.setattr(azure.identity, "ClientSecretCredential", lambda *a, **k: "credential")
    _add_tenant(repo, "sentinel", _SENTINEL_TENANT)
    return state


def _kql_refusal() -> Exception:
    from azure.core.exceptions import HttpResponseError

    error = HttpResponseError(message="BadArgumentError")
    error.error = types.SimpleNamespace(  # type: ignore[assignment]
        innererror={"innererror": {"message": "Failed to resolve table 'Nope'"}}
    )
    return error


def test_sentinel_valid_queries(azure: dict[str, Any]) -> None:
    code, payload = _validate_json("sentinel")

    assert code == 0, payload
    # rule-0001 and rule-0008 are the corpus's Sentinel rules.
    _passed("sentinel", payload, queries=2)
    assert len(azure["queries"]) == 2
    _no_flags()


def test_sentinel_valid_queries_text(azure: dict[str, Any]) -> None:
    code, output = _validate_text("sentinel")

    assert code == 0, output
    assert "2 queries valid on 1 tenant" in output


def test_sentinel_refused_query(azure: dict[str, Any]) -> None:
    azure["answer"] = _kql_refusal()

    code, payload = _validate_json("sentinel")

    assert code == 1, payload
    _rejected("sentinel", payload, queries=2)


def test_sentinel_refused_query_text(azure: dict[str, Any]) -> None:
    azure["answer"] = _kql_refusal()

    code, output = _validate_text("sentinel")

    assert code == 1, output
    assert "Queries rejected on sentinel · 2 checked on 1 tenant" in output
    # The parser's message names the rejected query's problem.
    assert "Failed to resolve table 'Nope'" in output


def test_strict_is_refused_with_live(azure: dict[str, Any]) -> None:
    """A tenant accepts or rejects a query: ``--strict`` has nothing to grade."""
    result = runner.invoke(
        app, ["--json", "validate", "query", "--platform", "sentinel", "--live", "--strict"]
    )

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["message"] == (
        "--strict applies to the offline check: a tenant accepts or rejects a query"
    )
    assert azure["queries"] == []


# --------------------------------------------------------------------------
# Defender: the Graph session behind runHuntingQuery
# --------------------------------------------------------------------------

_DEFENDER_TENANT = 'ssl = true\ntenant_id = "t"\nclient_id = "c"\nclient_secret = "s"\n'
_DEFENDER_COLUMNS = [{"name": "Timestamp"}, {"name": "DeviceId"}, {"name": "ReportId"}]


@pytest.fixture
def graph(repo: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import opentide.platforms.defender_for_endpoint.client as client

    state: dict[str, Any] = {"answer": FakeResponse(body={"schema": _DEFENDER_COLUMNS})}
    sessions: list[FakeSession] = []

    def _session(**_kwargs: Any) -> FakeSession:
        session = FakeSession(lambda *_args: state["answer"])
        sessions.append(session)
        return session

    monkeypatch.setattr(client.DefenderForEndpointService, "_connect_to_tenant", lambda *a: "t")
    monkeypatch.setattr(client, "TenantSession", _session)
    state["sessions"] = sessions
    _add_tenant(repo, "defender_for_endpoint", _DEFENDER_TENANT)
    return state


def _hunting_queries(state: dict[str, Any]) -> list[str]:
    return [
        call[2]["json"]["Query"]
        for session in state["sessions"]
        for call in session.calls
        if call[1].endswith("/runHuntingQuery")
    ]


def test_defender_valid_query(graph: dict[str, Any]) -> None:
    code, payload = _validate_json("defender_for_endpoint")

    assert code == 0, payload
    _passed("defender_for_endpoint", payload, queries=1)
    [query] = _hunting_queries(graph)
    assert query.startswith("DeviceProcessEvents")
    _no_flags()


def test_defender_refused_query(graph: dict[str, Any]) -> None:
    graph["answer"] = FakeResponse(400, {"error": {"message": "Syntax error near 'take'"}})

    code, payload = _validate_json("defender_for_endpoint")

    assert code == 1, payload
    _rejected("defender_for_endpoint", payload, queries=1)


def test_defender_query_missing_a_required_column_is_rejected(graph: dict[str, Any]) -> None:
    """A query Graph runs, whose output lacks ``ReportId``, cannot be a custom detection."""
    graph["answer"] = FakeResponse(body={"schema": _DEFENDER_COLUMNS[:2]})

    code, payload = _validate_json("defender_for_endpoint")

    assert code == 1, payload
    _rejected("defender_for_endpoint", payload, queries=1)


def test_defender_missing_column_text_names_the_rule(graph: dict[str, Any]) -> None:
    graph["answer"] = FakeResponse(body={"schema": _DEFENDER_COLUMNS[:2]})

    code, output = _validate_text("defender_for_endpoint")

    assert code == 1, output
    assert "Queries rejected on defender_for_endpoint · 1 checked on 1 tenant" in output
    assert "Defender KQL Rule (00000000-0000-4000-8003-000000000002)" in output
    assert "Detected Defender XDR tables: DeviceProcessEvents" in output


# --------------------------------------------------------------------------
# Splunk: a local stand-in serving search/parser
# --------------------------------------------------------------------------


@pytest.fixture
def splunk(repo: Path, tmp_path: Path) -> Iterator[SplunkStandIn]:
    (tmp_path / "splunk").mkdir()
    with serve_splunk(tmp_path / "splunk") as stand_in:
        _add_tenant(
            repo,
            "splunk",
            f'ssl = false\nurl = "localhost"\nport = {stand_in.port}\napp = "search"\n'
            'token = "token"\n',
        )
        yield stand_in


def _parsed(stand_in: SplunkStandIn) -> int:
    return sum(path.endswith("parser") for _, path, _ in stand_in.requests)


def test_splunk_valid_query(splunk: SplunkStandIn) -> None:
    code, payload = _validate_json("splunk")

    assert code == 0, payload
    _passed("splunk", payload, queries=1)
    # A parse, not a search: Splunk runs no job for a live check.
    assert _parsed(splunk) == 1
    assert not any("/search/jobs" in path for _, path, _ in splunk.requests)
    _no_flags()


def test_splunk_refused_query(repo: Path, splunk: SplunkStandIn) -> None:
    _edit_rule(repo, "rule-0003-splunk-spl.yaml", "| head 1", "|badcommand")

    code, payload = _validate_json("splunk")

    assert code == 1, payload
    _rejected("splunk", payload, queries=1)


def test_splunk_refused_query_text(repo: Path, splunk: SplunkStandIn) -> None:
    _edit_rule(repo, "rule-0003-splunk-spl.yaml", "| head 1", "|badcommand")

    code, output = _validate_text("splunk")

    assert code == 1, output
    assert "Queries rejected on splunk · 1 checked on 1 tenant" in output


def test_splunk_parser_timeout_is_a_warning(repo: Path, splunk: SplunkStandIn) -> None:
    """A gateway's 307 'Network Error' answering the parse is assumed valid, with a warning."""
    _edit_rule(repo, "rule-0003-splunk-spl.yaml", "| head 1", "|unreachable")

    code, payload = _validate_json("splunk")

    assert code == 0, payload
    _warned("splunk", payload, queries=1)


# --------------------------------------------------------------------------
# SentinelOne: the session behind dv/events/pq
# --------------------------------------------------------------------------

_S1_TENANT = 'ssl = true\nurl = "https://s1.example"\naccount_id = 42\napi_token = "tok"\n'
_S1_FINISHED = {"data": {"queryId": "q-1", "status": "FINISHED", "columns": [], "data": []}}


@pytest.fixture
def s1(repo: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import opentide.platforms.sentinel_one.client as client

    state: dict[str, Any] = {"answer": FakeResponse(body=_S1_FINISHED), "sessions": []}

    def _session(**_kwargs: Any) -> FakeSession:
        session = FakeSession(lambda *_args: state["answer"])
        state["sessions"].append(session)
        return session

    monkeypatch.setattr(client, "TenantSession", _session)
    _add_tenant(repo, "sentinel_one", _S1_TENANT)
    return state


def _s1_queries(state: dict[str, Any]) -> list[str]:
    queries = []
    for session in state["sessions"]:
        for method, url, kwargs in session.calls:
            if method == "POST" and url.endswith("/dv/events/pq"):
                body = kwargs.get("json") or json.loads(kwargs["data"])
                queries.append(str(body["query"]))
    return queries


def test_sentinel_one_valid_query(s1: dict[str, Any]) -> None:
    code, payload = _validate_json("sentinel_one")

    assert code == 0, payload
    _passed("sentinel_one", payload, queries=1)
    [query] = _s1_queries(s1)
    assert query.startswith('EventType = "Process Create"')
    _no_flags()


def test_sentinel_one_refused_query(s1: dict[str, Any]) -> None:
    s1["answer"] = FakeResponse(400, {"errors": [{"detail": "Unknown field EventTyp"}]})

    code, payload = _validate_json("sentinel_one")

    assert code == 1, payload
    _rejected("sentinel_one", payload, queries=1)


def test_sentinel_one_refused_query_text(s1: dict[str, Any]) -> None:
    s1["answer"] = FakeResponse(400, {"errors": [{"detail": "Unknown field EventTyp"}]})

    code, output = _validate_text("sentinel_one")

    assert code == 1, output
    assert "Queries rejected on sentinel_one · 1 checked on 1 tenant" in output
    assert "Unknown field EventTyp" in output


# --------------------------------------------------------------------------
# Carbon Black Cloud: the SDK's search_validation call
# --------------------------------------------------------------------------

_CBC_TENANT = 'ssl = true\nurl = "https://cbc.example"\norg_key = "ORG"\ntoken = "tok"\n'


@pytest.fixture
def cbc(repo: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    from cbc_sdk.rest_api import CBCloudAPI

    state: dict[str, Any] = {"valid": True, "validated": []}

    def _validate(_api: object, query: str) -> bool:
        state["validated"].append(query)
        return bool(state["valid"])

    def _no_search(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a live check must not run a process search on Carbon Black")

    monkeypatch.setattr(CBCloudAPI, "validate_process_query", _validate)
    monkeypatch.setattr(CBCloudAPI, "select", _no_search)
    _add_tenant(repo, "carbon_black_cloud", _CBC_TENANT)
    return state


def test_carbon_black_valid_query(cbc: dict[str, Any]) -> None:
    code, payload = _validate_json("carbon_black_cloud")

    assert code == 0, payload
    _passed("carbon_black_cloud", payload, queries=1)
    assert cbc["validated"] == ["process_name:cmd.exe"]
    _no_flags()


def test_carbon_black_refused_query(cbc: dict[str, Any]) -> None:
    cbc["valid"] = False

    code, payload = _validate_json("carbon_black_cloud")

    assert code == 1, payload
    _rejected("carbon_black_cloud", payload, queries=1)


def test_carbon_black_refused_query_text(cbc: dict[str, Any]) -> None:
    cbc["valid"] = False

    code, output = _validate_text("carbon_black_cloud")

    assert code == 1, output
    assert "Queries rejected on carbon_black_cloud · 1 checked on 1 tenant" in output


# --------------------------------------------------------------------------
# Elastic: Kibana's rule preview
# --------------------------------------------------------------------------


@pytest.fixture
def kibana(repo: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    from opentide.platforms.elastic.client import ElasticClient

    state: dict[str, Any] = {"preview": {"logs": []}, "previews": [], "searches": []}

    def _preview(_client: object, payload: dict[str, Any], **_kwargs: Any) -> FakeResponse:
        state["previews"].append(payload)
        return FakeResponse(body=state["preview"])

    def _session_call(method: str, url: str, kwargs: dict[str, Any]) -> FakeResponse:
        state["searches"].append((method, url))
        # Field capabilities: the index has the event timestamp the rule needs.
        return FakeResponse(
            body={
                "indices": ["logs-1"],
                "fields": {"@timestamp": {"date": {"type": "date", "aggregatable": True}}},
            }
        )

    original = ElasticClient.__init__

    def _init(self: ElasticClient, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        self.session = FakeSession(_session_call)  # type: ignore[assignment]

    monkeypatch.setattr(ElasticClient, "__init__", _init)
    monkeypatch.setattr(ElasticClient, "preview_rule", _preview)
    monkeypatch.setenv("ELASTIC_API_KEY", "key")
    return state


def test_elastic_valid_rule(kibana: dict[str, Any]) -> None:
    code, payload = _validate_json("elastic")

    assert code == 0, payload
    # The corpus tenant is `staging`, which takes PREVIEW rules only.
    _passed("elastic", payload, queries=1, tenant="staging")
    [previewed] = kibana["previews"]
    assert previewed["query"].strip() == 'process.name: "powershell.exe"'
    _no_flags()


def test_elastic_preview_error_rejects_the_rule(kibana: dict[str, Any]) -> None:
    kibana["preview"] = {"logs": [{"errors": ["Unknown field 'foo.bar' in query"]}]}

    code, payload = _validate_json("elastic")

    assert code == 1, payload
    _rejected("elastic", payload, queries=1, tenant="staging")


def test_elastic_preview_error_text(kibana: dict[str, Any]) -> None:
    kibana["preview"] = {"logs": [{"errors": ["Unknown field 'foo.bar' in query"]}]}

    code, output = _validate_text("elastic")

    assert code == 1, output
    assert "Queries rejected on elastic · 1 checked on 1 tenant" in output
    assert "Unknown field 'foo.bar' in query" in output


def test_elastic_preview_warning_warns(kibana: dict[str, Any]) -> None:
    kibana["preview"] = {"logs": [{"warnings": ["index logs-* matched no data"]}]}

    code, payload = _validate_json("elastic")

    assert code == 0, payload
    _warned("elastic", payload, queries=1, tenant="staging")


def test_elastic_advisory_warns(repo: Path, kibana: dict[str, Any]) -> None:
    """A rule-shape advisory (here ``lookback_zero``) is a warning on top of the preview."""
    _edit_rule(repo, "rule-0009-elastic-kql.yaml", "lookback: 1m", "lookback: 0m")

    code, payload = _validate_json("elastic")

    assert code == 0, payload
    _warned("elastic", payload, queries=1, tenant="staging")


def test_elastic_tenant_refusing_the_preview_rejects(kibana: dict[str, Any]) -> None:
    kibana["preview"] = {"logs": [{"errors": ["missing privileges for .preview.alerts-x"]}]}

    code, payload = _validate_json("elastic")

    assert code == 1, payload
    _rejected("elastic", payload, queries=1, tenant="staging")


# --------------------------------------------------------------------------
# CrowdStrike and HarfangLab: no live validation, never a fake pass
# --------------------------------------------------------------------------


@pytest.mark.parametrize("platform", ["crowdstrike", "harfanglab"])
def test_platforms_without_validation_are_unsupported(repo: Path, platform: str) -> None:
    code, payload = _validate_json(platform)

    message = f"query validation not supported for {platform}"
    assert code == 1, payload
    assert payload == {
        "platform": platform,
        "valid": None,
        "supported": False,
        "ok": False,
        "status": "failed",
        "message": message,
        "error": message,
        "schema_version": 1,
        "command": "validate query",
        "exit_code": 1,
        "summary": {},
        "next_actions": [],
        "failure": _failure(message),
    }


@pytest.mark.parametrize("platform", ["crowdstrike", "harfanglab"])
def test_platforms_without_validation_are_unsupported_text(repo: Path, platform: str) -> None:
    code, output = _validate_text(platform)

    assert code == 1, output
    assert f"query validation not supported for {platform}" in output


# --------------------------------------------------------------------------
# The SDK: DetectionRule.validate_query on the same stand-ins
# --------------------------------------------------------------------------


def _sdk_rule(platform: str) -> Any:
    from opentide.core.registry import Opentide

    Opentide.reload()
    return Opentide.Rules[CORPUS_RULE_UUIDS[platform]]


def _sdk(platform: str) -> tuple[bool, list[str], list[str]]:
    result = _sdk_rule(platform).validate_query(platform)
    return result.ok, list(result.errors), list(result.warnings)


def test_sdk_valid_query(azure: dict[str, Any]) -> None:
    assert _sdk("sentinel") == (True, [], [])
    _no_flags()


def test_sdk_refused_query(azure: dict[str, Any]) -> None:
    azure["answer"] = _kql_refusal()

    assert _sdk("sentinel") == (False, ["Query validation failed for sentinel"], [])


def test_sdk_warning(repo: Path, splunk: SplunkStandIn) -> None:
    _edit_rule(repo, "rule-0003-splunk-spl.yaml", "| head 1", "|unreachable")

    assert _sdk("splunk") == (True, [], ["Query validation reported warnings for splunk"])


def test_sdk_leaves_the_callers_environment_alone(
    azure: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever the caller's process environment holds is neither read nor changed."""
    with monkeypatch.context() as patched:
        patched.setenv("VALIDATION_ERROR_RAISED", "True")

        assert _sdk("sentinel") == (True, [], [])
        assert os.environ["VALIDATION_ERROR_RAISED"] == "True"
