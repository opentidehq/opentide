"""Exabeam Search: ``opentide query``, ``validate query --live``, a rule's queries (exabeam-1.0)."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import requests
import yaml

from opentide.core.errors import Errors
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.exabeam.client import PACER, TOKEN_PATH
from opentide.platforms.exabeam.compile import SEARCH_PATH
from opentide.platforms.exabeam.runner import (
    MAX_ROWS,
    ExabeamQueryRunner,
    selected_columns,
)
from opentide.platforms.exabeam.validator import ExabeamQueryValidator, declare
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow
from opentide.query.rules import RuleQueryError, rule_queries

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "exabeam"
Tenant = ConfigurationModels.Systems.Exabeam.Tenant
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=datetime(2026, 11, 11, 11, 0, tzinfo=timezone.utc), end=NOW)


def _response(status: int, body: Any = None, *, text: str = "") -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode("utf-8") if body is not None else text.encode()
    if body is not None:
        response.headers["Content-Type"] = "application/json"
    return response


def _tenant(**setup: Any) -> Any:
    values = {field.name: None for field in dataclasses.fields(Tenant.Setup)} | {
        "ssl": True,
        "region": "eu",
        "client_id": "id",
        "client_secret": "secret",
        "test_mode": False,
    }
    return Tenant(name="exabeam-eu", description="", setup=Tenant.Setup(**(values | setup)))


class FakeSearch:
    """The token and Search endpoints; ``answer`` is the search's response."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.searches: list[dict[str, Any]] = []
        self.timeouts: list[float] = []
        self.closed = False

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        if url.endswith(TOKEN_PATH):
            return _response(200, {"access_token": "t"})
        assert (method, url) == ("POST", "https://api.eu.exabeam.cloud" + SEARCH_PATH)
        assert kwargs["headers"]["Authorization"] == "Bearer t"
        self.searches.append(kwargs["json"])
        self.timeouts.append(kwargs["timeout"])
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _pacer() -> None:
    PACER.reset()


#: The one tenant the runner tests use: the runner keeps one client per tenant object.
TENANT = _tenant()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client the tests did not wire to a fake must never reach a real tenant."""

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("a test reached the network")

    monkeypatch.setattr(requests.Session, "request", refuse)


def _runner(fake: FakeSearch) -> ExabeamQueryRunner:
    runner = ExabeamQueryRunner()
    client = runner._client(TENANT)
    client.session.request = fake.request  # type: ignore[method-assign]
    client.session.close = fake.close  # type: ignore[method-assign]
    return runner


def _request(text: str, limit: int = 10, **kwargs: Any) -> QueryRequest:
    return QueryRequest(
        platform="exabeam", text=text, window=WINDOW, limit=limit, timeout=7.0, **kwargs
    )


def test_a_hunt_is_the_filter_with_every_field() -> None:
    rows = [{"user": "a", "geo": {"country": "FR"}}, {"user": "b"}]
    fake = FakeSearch(_response(200, {"rows": rows, "totalRows": 2}))
    result = _runner(fake).run(_request(' activity_type:"app-login" '), TENANT)
    assert fake.searches == [
        {
            "filter": 'activity_type:"app-login"',
            "fields": ["*"],
            "startTime": "2026-11-11T11:00:00Z",
            "endTime": "2026-11-11T12:00:00Z",
            "limit": 11,
        }
    ]
    assert fake.timeouts == [7.0]
    assert [column.name for column in result.columns] == ["user", "geo.country"]
    assert result.rows == ({"user": "a", "geo.country": "FR"}, {"user": "b"})
    assert result.truncated is False
    assert result.language == "exabeam"


def test_more_rows_than_the_limit_are_truncated() -> None:
    fake = FakeSearch(_response(200, {"rows": [{"a": 1}, {"a": 2}, {"a": 3}], "totalRows": 3}))
    result = _runner(fake).run(_request("x", limit=2), TENANT)
    assert len(result.rows) == 2 and result.truncated


def test_the_limit_is_at_most_3000() -> None:
    fake = FakeSearch(_response(200, {"rows": [{"a": 1}], "totalRows": 9000}))
    result = _runner(fake).run(_request("x", limit=5000), TENANT)
    assert fake.searches[0]["limit"] == MAX_ROWS
    assert result.truncated, "totalRows says more matched"
    assert result.warnings == ("Exabeam returns at most 3,000 rows per search",)


def test_selected_columns_are_the_fields() -> None:
    query = (
        'SELECT host, COUNT(*) AS launches WHERE activity_type:"process-create" '
        "GROUP-BY host ORDER-BY launches DESC LIMIT 20"
    )
    fake = FakeSearch(_response(200, {"rows": []}))
    _runner(fake).run(_request(query), TENANT)
    assert fake.searches[0]["fields"] == ["host", "launches"]
    assert fake.searches[0]["filter"] == query


@pytest.mark.parametrize(
    ("query", "columns"),
    [
        ('activity_type:"x"', None),
        ("SELECT * WHERE a:1", None),
        ('select distinct user, RGX_EXTRACT(msg, "a,b") as part from t', ["user", "part"]),
        ("SELECT a | SELECT b", ["a"]),
        ("SELECT user", ["user"]),
    ],
)
def test_selected_columns(query: str, columns: list[str] | None) -> None:
    assert selected_columns(query) == columns


def test_a_400_refuses_the_query_with_exabeams_message() -> None:
    body = {"errors": [{"code": "BAD_QUERY", "message": "unexpected token"}], "traceId": "tr"}
    fake = FakeSearch(_response(400, body))
    with pytest.raises(QueryRefused) as caught:
        _runner(fake).run(_request("x:"), TENANT)
    assert caught.value.detail == "BAD_QUERY: unexpected token (traceId tr)"


def test_another_answer_is_an_error_never_a_pass() -> None:
    fake = FakeSearch(_response(502, text="Bad Gateway"))
    with pytest.raises(QueryRefused, match="HTTP 502"):
        _runner(fake).check(_request("x"), TENANT)


def test_an_answer_that_is_not_json_fails() -> None:
    fake = FakeSearch(_response(200, text="<html>"))
    with pytest.raises(QueryRefused, match="JSON"):
        _runner(fake).run(_request("x"), TENANT)


def test_a_refused_key_is_a_tenant_connection_error() -> None:
    fake = FakeSearch(_response(403, {"message": "forbidden"}))
    with pytest.raises(Errors.TenantConnectionError, match="exabeam_tenant_unauthorized"):
        _runner(fake).run(_request("x"), TENANT)


def test_a_runner_that_stops_waiting_closes_the_connection() -> None:
    fake = FakeSearch(requests.ReadTimeout("read timed out"))
    with pytest.raises(requests.ReadTimeout):
        _runner(fake).run(_request("x"), TENANT)
    assert fake.closed


def test_check_is_one_row_with_every_field() -> None:
    fake = FakeSearch(_response(200, {"rows": [{"a": 1}], "totalRows": 1}))
    found = _runner(fake).check(_request("x", limit=10), TENANT)
    assert fake.searches[0]["limit"] == 1
    assert fake.searches[0]["fields"] == ["*"]
    assert found.result is not None and len(found.result.rows) == 1
    assert found.warnings == ()


def test_the_tenant_url_follows_the_region_or_api_url() -> None:
    assert _tenant().setup.url == "https://api.eu.exabeam.cloud"
    assert _tenant(region="us-east").setup.url == "https://api.us-east.exabeam.cloud"
    assert _tenant(api_url="https://gw.example/").setup.url == "https://gw.example"


def test_another_tenant_kind_is_refused() -> None:
    with pytest.raises(TypeError, match="Exabeam tenant"):
        ExabeamQueryRunner()._client(object())  # type: ignore[arg-type]


# --- the rule's queries and the live check -------------------------------------------


def _rule(name: str) -> Any:
    return load_rule_from_dict(yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8")))


def test_each_sequence_is_one_query() -> None:
    queries = rule_queries(_rule("rule-exabeam-sequence-1.0.yaml"), "exabeam")
    assert [query.label for query in queries] == ["sequence 1", "sequence 2"]
    assert all(query.language == "exabeam" for query in queries)
    assert queries[0].text.startswith('activity_type:"process-create"\n')
    assert queries[1].note is not None and "condition" in queries[1].note
    (single,) = rule_queries(_rule("block-exabeam.yaml"), "exabeam")
    assert single.label is None and single.note is None


def test_a_block_without_sequences_has_no_query() -> None:
    from types import SimpleNamespace

    from opentide.query.rules import _exabeam_queries

    with pytest.raises(RuleQueryError, match="no Exabeam sequences"):
        _exabeam_queries(SimpleNamespace(sequences=[]), _rule("block-exabeam.yaml"))


class _Recording(ExabeamQueryRunner):
    def __init__(self) -> None:
        self.requests: list[QueryRequest] = []

    def check(self, request: QueryRequest, tenant: Any) -> Any:
        from opentide.query.models import LiveCheck

        self.requests.append(request)
        return LiveCheck()


def test_live_checks_each_filter_over_the_last_15_minutes() -> None:
    runner = _Recording()
    validator = ExabeamQueryValidator(runner)
    checks = validator.check_rule(
        _rule("rule-exabeam-sequence-1.0.yaml"), _tenant(), TimeWindow(start=NOW, end=NOW)
    )
    assert [check.ok for check in checks] == [True, True]
    assert [request.label for request in runner.requests] == ["sequence 1", "sequence 2"]
    for request in runner.requests:
        assert request.limit == 1
        assert request.window == TimeWindow(
            start=datetime(2026, 11, 11, 11, 45, tzinfo=timezone.utc), end=NOW
        )
    assert isinstance(declare(), ExabeamQueryValidator)


def test_live_reports_a_refused_filter_as_that_sequences_failure() -> None:
    class Refusing(_Recording):
        def check(self, request: QueryRequest, tenant: Any) -> Any:
            self.requests.append(request)
            if request.label == "sequence 2":
                raise QueryRefused("Exabeam refused the query on exabeam-eu", detail="bad")
            return super().check(request, tenant)

    checks = ExabeamQueryValidator(Refusing()).check_rule(
        _rule("rule-exabeam-sequence-1.0.yaml"), _tenant(), TimeWindow(start=NOW, end=NOW)
    )
    assert [check.ok for check in checks] == [True, False]
    assert checks[1].errors == ("Exabeam refused the query on exabeam-eu: bad",)
