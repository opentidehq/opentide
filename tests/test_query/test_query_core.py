"""The parts of ``opentide query`` every platform shares: window, tenants, rule queries, service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

import pytest

from opentide.core.errors import Errors
from opentide.core.io import load_yaml
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels as C
from opentide.models.system_config import SystemConfig
from opentide.query.models import (
    QueryColumn,
    QueryRefused,
    QueryRequest,
    QueryResult,
    TenantOutcome,
    flatten,
)
from opentide.query.rules import RuleQueryError, rule_queries
from opentide.query.runner import QueryRunner, kql_with_limit
from opentide.query.service import QueryUsageError, run_query
from opentide.query.tenants import TenantSelectionError, select_tenants
from opentide.query.window import WindowError, resolve_window

NOW = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
RULES = Path(__file__).resolve().parents[1] / "fixtures/tide_corpus/current/Objects/Detection Rules"


# --------------------------------------------------------------------------
# window
# --------------------------------------------------------------------------


def test_the_default_window_is_the_last_day() -> None:
    window = resolve_window(now=NOW)
    assert (window.start, window.end) == (NOW - timedelta(hours=24), NOW)


@pytest.mark.parametrize(("since", "seconds"), [("15m", 900), ("7d", 604800), ("PT1H", 3600)])
def test_since_takes_short_and_iso_durations(since: str, seconds: int) -> None:
    window = resolve_window(since, now=NOW)
    assert window.seconds == seconds and window.end == NOW


def test_since_counts_back_from_to() -> None:
    window = resolve_window("1h", end="2026-10-01T12:00:00Z", now=NOW)
    assert window.start == datetime(2026, 10, 1, 11, 0, tzinfo=timezone.utc)


def test_from_and_to_read_offsets_and_default_to_utc() -> None:
    window = resolve_window(start="2026-10-01T10:00:00+02:00", end="2026-10-01T09:00:00")
    assert window.start == datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
    assert window.end == datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
    assert window.to_dict() == {
        "from": "2026-10-01T08:00:00.000Z",
        "to": "2026-10-01T09:00:00.000Z",
    }


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"since": "1h", "start": "2026-10-01"}, "--since cannot be combined with --from"),
        ({"since": "yesterday"}, "not a duration"),
        ({"since": "0s"}, "not a duration"),
        ({"start": "October"}, "not an ISO-8601 time"),
        ({"start": "2026-10-02", "end": "2026-10-01"}, "earlier than --to"),
    ],
)
def test_a_window_that_cannot_be_used_names_the_flag(kwargs: dict[str, str], message: str) -> None:
    with pytest.raises(WindowError, match=message):
        resolve_window(**kwargs, now=NOW)


# --------------------------------------------------------------------------
# KQL limit
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("query", "sent"),
    [
        ("T", "T\n| take 11"),
        ("T | take 5", "T | take 5"),
        ("T | LIMIT 5;", "T | LIMIT 5"),
        ("T | take 5 // the five newest", "T | take 5 // the five newest"),
        # Text that only looks like a take: in a comment, in a string.
        ("T // | take 3", "T // | take 3\n| take 11"),
        ('T | where Url == "a | take 3"', 'T | where Url == "a | take 3"\n| take 11'),
        ("T | where A == @'c:\\ | take 3'", "T | where A == @'c:\\ | take 3'\n| take 11"),
    ],
)
def test_kql_takes_one_row_past_the_limit_unless_the_query_already_takes(
    query: str, sent: str
) -> None:
    assert kql_with_limit(query, 10) == sent


# --------------------------------------------------------------------------
# tenants
# --------------------------------------------------------------------------


def _tenant(name: str) -> C.Systems.Splunk.Tenant:
    setup = C.Systems.Splunk.Tenant.Setup(ssl=True, url="h", port=1, app="a", token="t")
    return C.Systems.Splunk.Tenant(name=name, description="", setup=setup)


TENANTS = [_tenant("lab"), _tenant("prod"), _tenant("dr")]


def _names(tenants: list[SystemConfig.Tenant]) -> list[str]:
    return [tenant.name for tenant in tenants]


def test_no_name_selects_the_only_tenant() -> None:
    assert _names(select_tenants("splunk", [], TENANTS[:1])) == ["lab"]


def test_no_name_with_several_tenants_asks_for_one_or_all() -> None:
    with pytest.raises(TenantSelectionError, match="3 tenants") as refused:
        select_tenants("splunk", [], TENANTS)
    assert refused.value.choices == ("lab", "prod", "dr", "all")


def test_all_selects_every_tenant() -> None:
    assert _names(select_tenants("splunk", ["all"], TENANTS)) == ["lab", "prod", "dr"]


def test_names_select_in_configuration_order_once() -> None:
    assert _names(select_tenants("splunk", ["dr", "lab", "dr"], TENANTS)) == ["lab", "dr"]


def test_an_unknown_name_is_refused_with_the_configured_ones() -> None:
    with pytest.raises(TenantSelectionError, match="no tenant named 'prd'") as refused:
        select_tenants("splunk", ["prd"], TENANTS)
    assert refused.value.value == "prd"
    assert "prod" in refused.value.choices


def test_all_with_a_name_is_refused() -> None:
    with pytest.raises(TenantSelectionError, match="already selects every tenant"):
        select_tenants("splunk", ["all", "lab"], TENANTS)


def test_no_tenant_configured_names_the_file_to_add_one_to(tide_corpus_repo: Path) -> None:
    with pytest.raises(TenantSelectionError, match=r"no tenants configured.*sentinel\.toml"):
        select_tenants("sentinel", [], [])


# --------------------------------------------------------------------------
# rule queries
# --------------------------------------------------------------------------


def _rule(name: str) -> DetectionRule:
    path = RULES / name
    return load_rule_from_dict(load_yaml(path), file=path)


def test_a_kql_rule_sends_its_query() -> None:
    (item,) = rule_queries(_rule("rule-0002-defender-kql.yaml"), "defender_for_endpoint")
    assert item.text == "DeviceProcessEvents\n| take 1"
    assert item.label is None and item.note is None


def test_a_splunk_rule_sends_the_query_deploy_builds() -> None:
    (item,) = rule_queries(_rule("rule-0003-splunk-spl.yaml"), "splunk")
    assert item.text.startswith("index=main | head 1\n| eval MDR_UUID=")


def test_a_correlation_rule_sends_each_sub_query_with_a_label() -> None:
    (item,) = rule_queries(_rule("rule-0004-sentinel-one-s1ql.yaml"), "sentinel_one")
    assert item.text == 'EventType = "Process Create"'
    assert item.label == "sub-query 1"
    assert item.note is not None and "correlation" in item.note


def test_a_carbon_black_rule_is_one_line_as_deploy_sends_it() -> None:
    path = RULES / "rule-0005-carbon-black-lucene.yaml"
    data = load_yaml(path)
    data["configurations"]["carbon_black_cloud"]["query"] = (
        "process_name:cmd.exe\nAND parent_name:explorer.exe\n"
    )
    (item,) = rule_queries(load_rule_from_dict(data, file=path), "carbon_black_cloud")
    assert item.text == "process_name:cmd.exe AND parent_name:explorer.exe"


def test_an_elastic_query_rule_is_kuery_on_its_index() -> None:
    (item,) = rule_queries(_rule("rule-0009-elastic-kql.yaml"), "elastic")
    assert (item.language, item.index) == ("kuery", ("logs-*",))
    assert item.text == 'process.name: "powershell.exe"'


def test_a_harfanglab_rule_has_no_query_to_search_with() -> None:
    with pytest.raises(RuleQueryError, match="Sigma or YARA"):
        rule_queries(_rule("rule-0007-harfanglab-deploy-only.yaml"), "harfanglab")


def test_a_rule_without_the_platform_block_is_refused() -> None:
    with pytest.raises(RuleQueryError, match="no splunk configuration"):
        rule_queries(_rule("rule-0002-defender-kql.yaml"), "splunk")


# --------------------------------------------------------------------------
# models
# --------------------------------------------------------------------------


def test_flatten_dots_nested_objects_and_keeps_lists() -> None:
    assert flatten({"a": {"b": {"c": 1}}, "d": [1, {"e": 2}], "f": {}}) == {
        "a.b.c": 1,
        "d": [1, {"e": 2}],
        "f": {},
    }


def test_an_outcome_is_json_safe() -> None:
    import json

    result = QueryResult(
        columns=(QueryColumn("t"),),
        rows=({"t": NOW, "b": b"\x00\x01", "n": None},),
    )
    payload = TenantOutcome(tenant="lab", result=result).to_dict()
    assert json.loads(json.dumps(payload))["rows"] == [
        {"t": "2026-10-27T08:00:00.000Z", "b": "AAE=", "n": None}
    ]
    assert payload["status"] == "ok" and payload["row_count"] == 1


# --------------------------------------------------------------------------
# service
# --------------------------------------------------------------------------


class FakeRunner(QueryRunner):
    """Answers per tenant: rows, or the exception the test names for that tenant."""

    languages: ClassVar[tuple[str, ...]] = ("spl",)

    def __init__(self, failures: dict[str, Exception] | None = None) -> None:
        self.failures = failures or {}
        self.requests: list[tuple[str, QueryRequest]] = []

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        self.requests.append((tenant.name, request))
        if tenant.name in self.failures:
            raise self.failures[tenant.name]
        return QueryResult(columns=(QueryColumn("host"),), rows=({"host": tenant.name},))


@pytest.fixture
def tenants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("opentide.query.tenants.configured_tenants", lambda platform: TENANTS)


def test_one_failing_tenant_does_not_stop_the_others(tenants: None) -> None:
    runner = FakeRunner({"prod": QueryRefused("bad query", detail="line 1")})
    run = run_query("splunk", query="index=main", tenants=["all"], runner=runner, limit=5)
    assert [name for name, _ in runner.requests] == ["lab", "prod", "dr"]
    assert [o.ok for o in run.outcomes] == [True, False, True]
    assert (run.outcomes[1].error, run.outcomes[1].detail) == ("bad query", "line 1")
    assert run.ok is False and run.row_count == 2
    request = runner.requests[0][1]
    assert (request.limit, request.language, request.text) == (5, "spl", "index=main")


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (Errors.TenantConnectionError("401"), "cannot authenticate to splunk tenant 'lab': 401"),
        (ValueError("Splunk credentials are unset ($TOKEN)"), "credentials are unset"),
        (KeyError("results"), "KeyError: 'results'"),
    ],
)
def test_an_error_on_a_tenant_is_that_tenants_failure(
    tenants: None, error: Exception, message: str
) -> None:
    run = run_query("splunk", query="x", tenants=["lab"], runner=FakeRunner({"lab": error}))
    (outcome,) = run.outcomes
    assert outcome.ok is False
    assert message in str(outcome.error)


def test_an_unreachable_tenant_is_reported_with_its_address(tenants: None) -> None:
    import requests

    runner = FakeRunner({"lab": requests.ConnectionError("refused")})
    (outcome,) = run_query("splunk", query="x", tenants=["lab"], runner=runner).outcomes
    assert outcome.error is not None
    assert outcome.error.startswith("Cannot reach splunk tenant 'lab' at h")


def test_a_rule_query_note_is_a_warning(tenants: None) -> None:
    rule = _rule("rule-0004-sentinel-one-s1ql.yaml")

    class S1(FakeRunner):
        languages: ClassVar[tuple[str, ...]] = ("powerquery",)

    run = run_query("sentinel_one", rule=rule, tenants=["lab"], runner=S1())
    (outcome,) = run.outcomes
    assert outcome.label == "sub-query 1"
    assert "correlation" in outcome.to_dict()["warnings"][0]


def test_an_explicit_language_and_index_win_over_the_rules(tenants: None) -> None:
    runner = FakeRunner()
    runner.languages = ("esql", "eql", "lucene", "kuery")
    run_query(
        "elastic",
        rule=_rule("rule-0009-elastic-kql.yaml"),
        tenants=["lab"],
        language="lucene",
        index=["winlogbeat-*"],
        runner=runner,
    )
    request = runner.requests[0][1]
    assert (request.language, request.index) == ("lucene", ("winlogbeat-*",))


def test_a_raw_query_takes_the_platforms_default_language(tenants: None) -> None:
    runner = FakeRunner()
    run_query("elastic", query="FROM logs-*", tenants=["lab"], runner=runner)
    assert runner.requests[0][1].language == "esql"


@pytest.mark.parametrize(
    ("kwargs", "argument"),
    [
        ({"platform": "qradar", "query": "x"}, "--platform"),
        ({"platform": "splunk"}, "QUERY"),
        ({"platform": "splunk", "query": "   "}, "QUERY"),
        ({"platform": "splunk", "query": "x", "limit": 0}, "--limit"),
        ({"platform": "splunk", "query": "x", "limit": 10_001}, "--limit"),
        ({"platform": "splunk", "query": "x", "language": "kql"}, "--language"),
        ({"platform": "splunk", "query": "x", "since": "nope"}, "--since"),
        ({"platform": "splunk", "query": "x", "tenants": ["nope"]}, "--tenant"),
        ({"platform": "splunk", "query": "x", "timeout": 0}, "--timeout"),
    ],
)
def test_a_call_that_cannot_run_contacts_no_tenant(
    tenants: None, kwargs: dict[str, Any], argument: str
) -> None:
    runner = FakeRunner()
    platform = kwargs.pop("platform")
    with pytest.raises(QueryUsageError) as refused:
        run_query(platform, runner=runner, **kwargs)
    assert refused.value.argument == argument
    assert runner.requests == []


def test_a_rule_with_no_runnable_query_is_a_usage_error(tenants: None) -> None:
    with pytest.raises(QueryUsageError, match="Sigma") as refused:
        run_query("harfanglab", rule=_rule("rule-0007-harfanglab-deploy-only.yaml"))
    assert refused.value.argument == "--rule"


def test_a_runner_that_cannot_load_fails_every_tenant(
    tenants: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.query.runner import RunnerUnavailable

    def broken(platform: str) -> QueryRunner:
        raise RunnerUnavailable("cannot load the splunk query runner: No module named 'splunklib'")

    monkeypatch.setattr("opentide.query.service.load_runner", broken)
    run = run_query("splunk", query="x", tenants=["all"])
    assert [o.ok for o in run.outcomes] == [False, False, False]
    assert "splunklib" in str(run.outcomes[0].error)


def test_the_rule_sdk_method_runs_the_rules_query(
    tenants: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("opentide.query.service.load_runner", lambda platform: runner)
    rule = _rule("rule-0003-splunk-spl.yaml")
    run = rule.run_query("splunk", tenants=["prod"], since="1h", limit=3)
    assert run.rule is rule and run.tenants == ["prod"]
    assert run.window.seconds == 3600
    assert runner.requests[0][1].text.startswith("index=main | head 1")


def test_the_package_exports_resolve_lazily() -> None:
    import opentide.query as package

    assert sorted(package.__all__) == sorted(package._EXPORTS)
    for name in package.__all__:
        assert getattr(package, name) is not None
    with pytest.raises(AttributeError):
        _ = package.nothing_here
