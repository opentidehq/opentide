"""``opentide query`` and ``validate query --live`` on Graylog (graylog-1.0, Query validation).

The HTTP boundary is a fake behind :meth:`GraylogClient.request`'s session;
the runner, the validator and the client are real.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import requests
import yaml

from opentide.core.errors import Errors
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.graylog import runner as runner_module
from opentide.platforms.graylog.client import GraylogClient
from opentide.platforms.graylog.runner import (
    GraylogQueryRunner,
    requested_fields,
    resolve_streams,
)
from opentide.platforms.graylog.validator import GraylogQueryValidator, declare
from opentide.query.check import check_window
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow
from opentide.query.rules import rule_queries

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "graylog"
Tenant = ConfigurationModels.Systems.Graylog.Tenant
URL = "https://graylog.example.com"
STREAM = "65f0c0ffee0123456789abcd"
END = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
WINDOW = TimeWindow(start=END - timedelta(hours=1), end=END)


def _tenant(**setup: Any) -> Any:
    values = {field.name: None for field in dataclasses.fields(Tenant.Setup)} | {
        "ssl": True,
        "url": URL,
        "token": "t",
        "streams": ["sysmon"],
        "stream_ids": {"sysmon": STREAM, "security": "65f0c0ffee0123456789abce"},
    }
    return Tenant(name="graylog-prod", description="", setup=Tenant.Setup(**(values | setup)))


def _response(status: int, body: Any) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


class Fake:
    def __init__(self, version: str = "7.2.2") -> None:
        self.version = version
        self.calls: list[tuple[str, str, Any]] = []
        self.answers: dict[str, requests.Response] = {}

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        path = url[len(URL) :]
        self.calls.append((method, path, kwargs.get("json")))
        if path in self.answers:
            return self.answers[path]
        if path == "/api/system":
            return _response(200, {"version": self.version})
        if path == "/api/search/validate":
            return _response(200, {"status": "OK", "explanations": []})
        if path == "/api/search/messages":
            return _response(
                200,
                {
                    "schema": [
                        {"column_type": "field", "type": "date", "field": "timestamp"},
                        {"column_type": "field", "type": "string", "field": "source"},
                        {"column_type": "field", "type": "unknown", "field": "winlog.user"},
                    ],
                    "datarows": [
                        ["2026-11-11T11:59:00.000Z", "host-1", "-"],
                        ["2026-11-11T11:58:00.000Z", "host-2", "alice"],
                    ],
                },
            )
        raise AssertionError(path)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Fake:
    fake = Fake()
    original = GraylogClient.__init__

    def init(self: GraylogClient, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        self.session.request = fake.request  # type: ignore[method-assign]

    monkeypatch.setattr(runner_module.GraylogClient, "__init__", init)
    return fake


def _request(text: str = "EventID:1", limit: int = 10, index: tuple[str, ...] = ()) -> QueryRequest:
    return QueryRequest(platform="graylog", text=text, window=WINDOW, limit=limit, index=index)


def test_run_searches_messages_read_only(fake: Fake) -> None:
    result = GraylogQueryRunner().run(_request(limit=1), _tenant())
    method, path, body = fake.calls[-1]
    assert (method, path) == ("POST", "/api/search/messages")
    assert body == {
        "query": "EventID:1",
        "streams": [STREAM],
        "timerange": {
            "type": "absolute",
            "from": "2026-11-11T11:00:00.000Z",
            "to": "2026-11-11T12:00:00.000Z",
        },
        "size": 2,
        "sort": "timestamp",
        "sort_order": "desc",
    }
    assert result.rows == ({"timestamp": "2026-11-11T11:59:00.000Z", "source": "host-1"},)
    assert result.truncated is True
    assert result.language == "lucene"
    assert [column.name for column in result.columns] == ["timestamp", "source", "winlog.user"]


def test_the_version_is_read_once_per_runner(fake: Fake) -> None:
    runner, tenant = GraylogQueryRunner(), _tenant()
    runner.run(_request(), tenant)
    runner.run(_request(), tenant)
    assert [call[1] for call in fake.calls].count("/api/system") == 1


@pytest.mark.parametrize(
    ("version", "fields"),
    [
        ((7, 2, 0), None),
        ((7, 1, 0), ["timestamp", "source", "message", "EventID", "winlog.user"]),
        ((7, 0, 16), ["timestamp", "source", "message", "EventID"]),
        ((6, 3, 5), ["timestamp", "source", "message", "EventID"]),
    ],
)
def test_requested_fields(version: tuple[int, int, int], fields: list[str] | None) -> None:
    query = "EventID:1 AND winlog.user:alice AND _exists_:EventID AND source:x"
    assert requested_fields(query, version) == fields


def test_before_7_2_the_search_names_its_fields(fake: Fake) -> None:
    fake.version = "6.3.5"
    GraylogQueryRunner().run(_request("winlog.user:alice"), _tenant())
    assert fake.calls[-1][2]["fields"] == ["timestamp", "source", "message"]


def test_streams_resolve_from_aliases_ids_and_the_tenant_default() -> None:
    tenant = _tenant()
    assert resolve_streams((), tenant) == [STREAM]
    assert resolve_streams(("security",), tenant) == ["65f0c0ffee0123456789abce"]
    assert resolve_streams(("000000000000000000000001",), tenant) == ["000000000000000000000001"]
    assert resolve_streams((), _tenant(streams=None)) == []
    with pytest.raises(QueryRefused, match="graylog_alias_unknown"):
        resolve_streams(("nowhere",), tenant)


def test_a_refused_search_is_query_refused(fake: Fake) -> None:
    fake.answers["/api/search/messages"] = _response(
        400, {"type": "ApiError", "message": "Failed to parse query [image:(foo]."}
    )
    with pytest.raises(QueryRefused) as caught:
        GraylogQueryRunner().run(_request("image:(foo"), _tenant())
    assert "Failed to parse query" in (caught.value.detail or "")


def test_a_refused_token_is_a_tenant_connection_error(fake: Fake) -> None:
    fake.answers["/api/system"] = _response(401, {})
    with pytest.raises(Errors.TenantConnectionError):
        GraylogQueryRunner().run(_request(), _tenant())
    fake.answers["/api/search/validate"] = _response(401, {})
    with pytest.raises(Errors.TenantConnectionError):
        GraylogQueryRunner().check(_request(), _tenant())


def test_check_asks_search_validate_over_the_window(fake: Fake) -> None:
    found = GraylogQueryRunner().check(_request(index=("security",)), _tenant())
    method, path, body = fake.calls[-1]
    assert (method, path) == ("POST", "/api/search/validate")
    assert body == {
        "query": "EventID:1",
        "streams": ["65f0c0ffee0123456789abce"],
        "timerange": {"type": "relative", "range": 3600},
    }
    assert found.warnings == ()
    assert all(call[1] != "/api/search/messages" for call in fake.calls), "no search runs"


def test_check_errors_refuse_and_warnings_carry_their_position(fake: Fake) -> None:
    fake.answers["/api/search/validate"] = _response(
        200,
        {
            "status": "WARNING",
            "explanations": [
                {
                    "error_type": "UNKNOWN_FIELD",
                    "begin_line": 1,
                    "begin_column": 0,
                    "error_title": "Unknown field",
                    "error_message": "Query contains unknown field: nosuch",
                }
            ],
        },
    )
    found = GraylogQueryRunner().check(_request(), _tenant())
    assert found.warnings == (
        "graylog_unknown_field: Unknown field: Query contains unknown field: nosuch "
        "(line 1, column 0)",
    )
    fake.answers["/api/search/validate"] = _response(
        200,
        {
            "status": "ERROR",
            "explanations": [
                {
                    "error_type": "QUERY_PARSING_ERROR",
                    "begin_line": 1,
                    "begin_column": 0,
                    "error_title": "Query parsing error",
                    "error_message": "Cannot parse query",
                }
            ],
        },
    )
    with pytest.raises(QueryRefused) as caught:
        GraylogQueryRunner().check(_request(), _tenant())
    assert caught.value.detail == "Query parsing error: Cannot parse query (line 1, column 0)"


def test_the_runner_refuses_another_platforms_tenant() -> None:
    with pytest.raises(TypeError):
        resolve_streams((), object())  # type: ignore[arg-type]


# --- the live validator --------------------------------------------------------------


def _rule(**block: Any) -> Any:
    document = yaml.safe_load((FIXTURES / "rule-graylog-aggregation-1.0.yaml").read_text())
    document["configurations"]["graylog"].update(block)
    return load_rule_from_dict(document)


def test_rule_queries_carry_the_block_streams() -> None:
    (query,) = rule_queries(_rule(), "graylog")
    assert query.language == "lucene"
    assert query.index == ("sysmon",)
    assert query.text.startswith("EventID:1")


def test_the_validator_checks_over_the_block_window(fake: Fake) -> None:
    (check,) = declare().check_rule(_rule(), _tenant(), check_window())
    assert check.ok
    _, _, body = fake.calls[-1]
    assert body["timerange"] == {"type": "relative", "range": 900}
    assert body["streams"] == [STREAM]


def test_the_validator_window_defaults_to_every(fake: Fake) -> None:
    rule = _rule(schedule={"every": "10m"})
    GraylogQueryValidator().check_rule(rule, _tenant(), check_window())
    assert fake.calls[-1][2]["timerange"]["range"] == 600


def test_the_validator_reports_a_refusal_as_the_rules_error(fake: Fake) -> None:
    fake.answers["/api/search/validate"] = _response(
        200, {"status": "ERROR", "explanations": [{"error_message": "bad"}]}
    )
    (check,) = GraylogQueryValidator().check_rule(_rule(), _tenant(), check_window())
    assert not check.ok
    assert "bad" in check.errors[0]
