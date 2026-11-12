"""``validate query --live`` and ``opentide query`` on Google SecOps (google-secops-1.0).

The live check compiles each rule's assembled text with ``verifyRuleText`` and
puts Google's diagnostics back on the section key and line; the query runner
searches with ``udmSearch``. The HTTP boundary is the fake Chronicle session of
the deployer tests.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
import requests
from tests.test_platforms.test_google_secops_compile import load_fixture_rule
from tests.test_platforms.test_google_secops_deployer import (
    ENDPOINT,
    INSTANCE,
    TENANT,
    FakeChronicle,
    FakeCredentials,
    _error,
    _response,
    _tenant,
)

from opentide.core.errors import Errors
from opentide.models.system_config import DeploymentBatch
from opentide.platforms.google_secops.client import GoogleSecopsClient, GoogleSecopsTenantError
from opentide.platforms.google_secops.compile import assemble
from opentide.platforms.google_secops.runner import (
    GoogleSecopsQueryRunner,
    search_result,
)
from opentide.platforms.google_secops.validator import GoogleSecopsValidator, check_rule
from opentide.query.check import QUERY_CHECK_TIMEOUT
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow
from opentide.query.rules import RuleQueryError, rule_queries

PROCESS = "rule-google-secops-process-1.0"


def _client(fake: FakeChronicle) -> GoogleSecopsClient:
    return GoogleSecopsClient(
        endpoint=ENDPOINT,
        instance=INSTANCE,
        credentials=FakeCredentials(),
        tenant=TENANT,
        sleep=lambda _s: None,
        session=fake,
    )


def _diagnostic(line: int, column: int, severity: str = "ERROR", **extra: Any) -> dict[str, Any]:
    return {
        "message": "field principal.nope does not exist",
        "severity": severity,
        "position": {"startLine": line, "startColumn": column, "endLine": line, "endColumn": 20},
        **extra,
    }


# --- verifyRuleText --------------------------------------------------------------------


def test_a_rule_that_compiles_passes() -> None:
    fake = FakeChronicle()
    rule = load_fixture_rule(PROCESS)
    check = check_rule(rule, _client(fake), TENANT)
    assert check.ok and check.warnings == ()
    assert fake.calls[0]["body"] == {"ruleText": assemble(rule).text}


def test_diagnostics_are_placed_on_their_section_key_and_line() -> None:
    rule = load_fixture_rule(PROCESS)
    events = assemble(rule).label_line("events")
    assert events is not None
    fake = FakeChronicle()
    fake.script.append(
        lambda _call: _response(
            200,
            {
                "compilationDiagnostics": [
                    _diagnostic(events + 3, 9, uri="https://cloud.google.com/chronicle/docs"),
                    _diagnostic(2, 5, severity="WARNING"),
                    {"message": "no position", "severity": "ERROR"},
                ]
            },
        )
    )
    check = check_rule(rule, _client(fake), TENANT)
    assert check.errors == (
        "google_secops_compile_error: configurations.google_secops.events line 3, column 5: "
        "field principal.nope does not exist (https://cloud.google.com/chronicle/docs)",
        "google_secops_compile_error: configurations.google_secops: no position",
    )
    assert check.warnings == (
        "google_secops_compile_warning: configurations.google_secops: field principal.nope does "
        "not exist",
    )


def test_a_refusal_without_diagnostics_still_fails() -> None:
    fake = FakeChronicle()
    fake.script.append(lambda _call: _response(200, {}))
    check = check_rule(load_fixture_rule(PROCESS), _client(fake), TENANT)
    assert check.errors == ("google_secops_compile_error: verifyRuleText did not report success",)


def test_a_frequency_google_does_not_allow_fails() -> None:
    fake = FakeChronicle()
    fake.allowed = ["LIVE_CUSTOMIZABLE"]
    check = check_rule(load_fixture_rule(PROCESS), _client(fake), TENANT)
    assert len(check.errors) == 1
    assert check.errors[0].startswith("google_secops_run_frequency_not_allowed: ")


def test_an_api_error_fails_the_rule_and_refused_credentials_raise() -> None:
    fake = FakeChronicle()
    fake.script.append(lambda _call: _error(400, "INVALID_ARGUMENT", "rule text too long"))
    check = check_rule(load_fixture_rule(PROCESS), _client(fake), TENANT)
    assert check.errors == ("verifyRuleText failed: INVALID_ARGUMENT: rule text too long",)
    fake.script.append(lambda _call: _error(401, "UNAUTHENTICATED", "bad token"))
    with pytest.raises(GoogleSecopsTenantError):
        check_rule(load_fixture_rule(PROCESS), _client(fake), TENANT)


class _Plan:
    """What TideDeployment would plan: one batch per tenant."""

    def __init__(self, batches: list[DeploymentBatch]) -> None:
        self.rule_deployment = batches


def _validate(monkeypatch: pytest.MonkeyPatch, fake: FakeChronicle, rules: list[Any]) -> Any:
    import opentide.deployment as deployment

    batch = DeploymentBatch(tenant=_tenant(), rules=rules)
    monkeypatch.setattr(deployment, "TideDeployment", lambda **_kwargs: _Plan([batch]))
    validator = GoogleSecopsValidator(client_factory=lambda _tenant, _timeout: _client(fake))
    return validator.validate(rules, timeout=5)


def test_the_validator_reports_one_check_per_rule_and_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeChronicle()
    rules = [load_fixture_rule(PROCESS), load_fixture_rule("rule-google-secops-spray-1.0")]
    report = _validate(monkeypatch, fake, rules)
    assert [check.ok for check in report.checks] == [True, True]
    assert report.platform == "google_secops"
    assert [call["path"].rsplit(":", 1)[-1] for call in fake.calls] == ["verifyRuleText"] * 2


def test_refused_credentials_fail_the_tenant_and_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeChronicle()
    fake.script.append(lambda _call: _error(403, "PERMISSION_DENIED", "denied"))
    rules = [load_fixture_rule(PROCESS), load_fixture_rule("rule-google-secops-spray-1.0")]
    report = _validate(monkeypatch, fake, rules)
    assert len(report.checks) == 1 and report.failed
    assert len(fake.calls) == 1


def test_a_check_with_no_answer_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeChronicle()

    def slow(_call: dict[str, Any]) -> Any:
        raise requests.ReadTimeout("read timed out")

    fake.script.extend([lambda call: fake._answer(call), slow])
    rules = [load_fixture_rule(PROCESS), load_fixture_rule("rule-google-secops-spray-1.0")]
    report = _validate(monkeypatch, fake, rules)
    assert [check.code for check in report.checks] == [None, QUERY_CHECK_TIMEOUT]


def test_credentials_that_do_not_load_fail_every_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    import opentide.deployment as deployment

    rules = [load_fixture_rule(PROCESS)]
    batch = DeploymentBatch(tenant=_tenant(), rules=rules)
    monkeypatch.setattr(deployment, "TideDeployment", lambda **_kwargs: _Plan([batch]))

    def refuse(_tenant: Any, _timeout: float) -> GoogleSecopsClient:
        raise GoogleSecopsTenantError("google_secops_credentials_missing", "no key")

    report = GoogleSecopsValidator(client_factory=refuse).validate(rules)
    assert report.failed and "no key" in report.checks[0].errors[0]


# --- opentide query --------------------------------------------------------------------

WINDOW = TimeWindow(
    start=datetime(2026, 11, 1, tzinfo=timezone.utc), end=datetime(2026, 11, 2, tzinfo=timezone.utc)
)


def _run(
    fake: FakeChronicle, text: str = 'metadata.event_type = "USER_LOGIN"', limit: int = 2
) -> Any:
    runner = GoogleSecopsQueryRunner()
    tenant = _tenant()
    runner.secops_client = lambda _tenant, timeout: _client(fake)  # type: ignore[method-assign]  # the test swaps in a fake client
    request = QueryRequest(platform="google_secops", text=text, window=WINDOW, limit=limit)
    return runner.run(request, tenant)


def test_a_search_sends_udm_search_with_the_yl2_dialect() -> None:
    fake = FakeChronicle()
    fake.script.append(
        lambda _call: _response(
            200,
            {
                "events": [
                    {"name": "e1", "udm": {"metadata": {"eventType": "USER_LOGIN"}}},
                    {"name": "e2", "udm": {"metadata": {"eventType": "USER_LOGIN"}}},
                ],
                "moreDataAvailable": False,
            },
        )
    )
    result = _run(fake)
    assert fake.calls == [
        {
            "method": "GET",
            "path": f"/v1/{INSTANCE}:udmSearch",
            "query": {
                "query": 'metadata.event_type = "USER_LOGIN"',
                "queryDialect": "YL2",
                "timeRange.startTime": "2026-11-01T00:00:00.000Z",
                "timeRange.endTime": "2026-11-02T00:00:00.000Z",
                "limit": "3",
            },
        }
    ]
    assert [column.name for column in result.columns] == ["metadata.eventType"]
    assert len(result.rows) == 2 and not result.truncated
    assert result.language == "yaral"


def test_more_data_is_a_truncation_warning() -> None:
    answer = {"events": {"events": [{"udm": {"a": 1}}] * 3}, "moreDataAvailable": True}
    result = search_result(answer, 2)
    assert result.truncated and len(result.rows) == 2
    assert result.warnings and "narrow" in result.warnings[0]


def test_statistics_become_rows() -> None:
    answer = {
        "stats": {
            "results": [
                {"column": "user", "values": [{"value": {"stringVal": "a"}}, {"value": {}}]},
                {"column": "n", "values": [{"value": {"int64Val": "5"}}]},
                {"column": "hosts", "values": [{"list": {"values": [{"stringVal": "h"}]}}] * 2},
            ],
            "tooManyResults": True,
        }
    }
    result = search_result(answer, 100)
    assert [column.name for column in result.columns] == ["user", "n", "hosts"]
    assert result.rows == (
        {"user": "a", "n": "5", "hosts": ["h"]},
        {"user": None, "n": None, "hosts": ["h"]},
    )
    assert result.truncated


def test_a_refused_search_and_refused_credentials() -> None:
    fake = FakeChronicle()
    fake.script.append(lambda _call: _error(400, "INVALID_ARGUMENT", "parse error at line 1"))
    with pytest.raises(QueryRefused) as refused:
        _run(fake)
    assert refused.value.detail == "parse error at line 1"
    fake.script.append(lambda _call: _error(403, "PERMISSION_DENIED", "udmSearch denied"))
    with pytest.raises(Errors.TenantConnectionError):
        _run(fake)


def test_a_limit_above_google_cap_is_capped() -> None:
    fake = FakeChronicle()
    fake.script.append(lambda _call: _response(200, {}))
    result = _run(fake, limit=20_000)
    assert fake.calls[0]["query"]["limit"] == "10000"
    assert result.rows == ()


def test_query_rule_is_not_supported() -> None:
    with pytest.raises(RuleQueryError, match="--rule is not supported for google_secops"):
        rule_queries(load_fixture_rule(PROCESS), "google_secops")


def test_the_runner_client_is_made_once_per_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    import opentide.platforms.google_secops.client as client_module

    made: list[Any] = []
    monkeypatch.setattr(client_module, "load_credentials", lambda value: made.append(value))
    runner = GoogleSecopsQueryRunner()
    tenant = _tenant()
    first = runner.secops_client(tenant, timeout=30)
    assert runner.secops_client(tenant, timeout=30) is first
    assert made == [None]
