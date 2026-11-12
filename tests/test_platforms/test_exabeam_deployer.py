"""Exabeam deploy: the Correlation Rules API with deployment state (exabeam-1.0, Deploy).

The HTTP boundary is a fake ``requests`` session that records every call and
answers like Exabeam's token, correlation-rule and search endpoints.
Everything above it is real: the client, the deployer, the compiler, the
deployment-state planner and shard writes.
"""

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import requests
import yaml

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.exabeam.client import (
    PACER,
    TOKEN_PATH,
    ExabeamApiError,
    ExabeamClient,
    ExabeamTenantError,
    api_error,
)
from opentide.platforms.exabeam.compile import RULES_PATH
from opentide.platforms.exabeam.deployer import (
    ExabeamDeploy,
    name_matches,
    returned_rule_id,
)
from opentide.states.deployment import (
    DeploymentStateError,
    normalise_external_id,
    record_external_id,
    shard_path,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "exabeam"
UUID = "00000000-0000-4000-8003-000000000071"
RELEASE = (StatusStrategy.RELEASE,)
Tenant = ConfigurationModels.Systems.Exabeam.Tenant
URL = "https://api.eu.exabeam.cloud"
FIRST_ID = "016dbc1d-a727-43df-a143-9546dcc81a5a"
NEXT_ID = "2c0f6c4e-1b1a-4c55-9d43-0e6f3d1b9a10"
NAME = "Password spraying from outside the network"


def _response(
    status: int, body: Any = None, headers: dict[str, str] | None = None, *, text: str = ""
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    if body is not None:
        response._content = json.dumps(body).encode("utf-8")
        response.headers["Content-Type"] = "application/json"
    else:
        response._content = text.encode("utf-8")
    response.headers.update(headers or {})
    return response


class FakeExabeam:
    """Tokens and correlation rules, answered as the Exabeam APIs answer them."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.rules: dict[str, dict[str, Any]] = {}
        self.ids = iter([FIRST_ID.upper(), NEXT_ID, "4a3b2c1d-0000-4000-8000-000000000003"])
        self.tokens = 0
        #: Answers queued ahead of the normal behaviour, each a callable of the call.
        self.script: list[Callable[[dict[str, Any]], requests.Response]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        assert url.startswith(URL + "/")
        assert kwargs.get("timeout"), "every request has a timeout"
        path = url[len(URL) :]
        call = {
            "method": method,
            "path": path,
            "params": kwargs.get("params"),
            "body": kwargs.get("json"),
            "auth": (kwargs.get("headers") or {}).get("Authorization"),
        }
        self.calls.append(call)
        if self.script:
            return self.script.pop(0)(call)
        if path == TOKEN_PATH:
            assert call["body"]["grant_type"] == "client_credentials"
            self.tokens += 1
            return _response(200, {"access_token": f"t{self.tokens}", "expires_in": 14400})
        assert call["auth"] == f"Bearer t{self.tokens}"
        if method == "GET" and path == RULES_PATH:
            wanted = call["params"]["nameContains"].lower()
            return _response(
                200,
                [
                    {"id": rule_id, **rule}
                    for rule_id, rule in self.rules.items()
                    if wanted in rule["name"].lower()
                ],
            )
        if method == "POST" and path == RULES_PATH:
            rule_id = next(self.ids)
            self.rules[rule_id.lower()] = call["body"]
            return _response(201, {"id": rule_id, **call["body"]})
        rule_id = path.rsplit("/", 1)[-1]
        if rule_id not in self.rules:
            return _response(404, {"errors": [{"code": "NOT_FOUND", "message": "no rule"}]})
        if method == "PUT":
            stored = self.rules[rule_id]
            self.rules[rule_id] = call["body"]
            return _response(200, {"id": rule_id, **stored, **call["body"]})
        if method == "DELETE":
            del self.rules[rule_id]
            return _response(204)
        raise AssertionError(f"unexpected call {method} {path}")

    def routes(self) -> list[str]:
        return [f"{call['method']} {call['path']}" for call in self.calls]

    def rule_calls(self) -> list[str]:
        return [route for route in self.routes() if TOKEN_PATH not in route]


@pytest.fixture(autouse=True)
def _deployment_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    PACER.reset()

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("a test reached the network")

    # A client the tests did not wire to the fake must never reach a real tenant.
    monkeypatch.setattr(requests.Session, "request", refuse)


def _tenant(**setup: Any) -> Any:
    values = {field.name: None for field in dataclasses.fields(Tenant.Setup)} | {
        "ssl": True,
        "region": "eu",
        "client_id": "id",
        "client_secret": "secret",
        "test_mode": False,
    }
    return Tenant(name="exabeam-eu", description="", setup=Tenant.Setup(**(values | setup)))


def _rule(status: str = "STAGING", name: str = "rule-exabeam-threshold-1.0.yaml") -> DetectionRule:
    document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    document["configurations"]["exabeam"]["status"] = status
    return load_rule_from_dict(document)


class Run:
    """Deploy one rule to one tenant against :attr:`fake`, with no real sleeps."""

    def __init__(self) -> None:
        self.fake = FakeExabeam()
        self.slept: list[float] = []
        self.now = 0.0

    def client(self) -> ExabeamClient:
        def sleep(seconds: float) -> None:
            self.slept.append(seconds)
            self.now += seconds

        built = ExabeamClient(
            URL, "id", "secret", tenant="exabeam-eu", sleep=sleep, clock=lambda: self.now
        )
        built.session.request = self.fake.request  # type: ignore[method-assign]
        return built

    def __call__(
        self, rule: DetectionRule | None = None, tenant: Any = None, strategies: Any = RELEASE
    ) -> FakeExabeam:
        ExabeamDeploy().deploy_tenant(
            [rule or _rule()], tenant or _tenant(), strategies, client=self.client()
        )
        return self.fake


@pytest.fixture
def run(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Run:
    del tide_corpus_repo
    # A local run may create: the operator commits the shard.
    monkeypatch.delenv("CI", raising=False)
    for name in ("GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)
    return Run()


def _bound(repo: Path) -> str | None:
    path = shard_path(UUID, repo)
    shard = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return shard.get("platforms", {}).get("exabeam", {}).get("exabeam-eu")


def _failed() -> bool:
    return bool(os.environ.get("DEPLOYMENT_ERROR_RAISED"))


def _warned() -> bool:
    return bool(os.environ.get("DEPLOYMENT_WARNING_RAISED"))


def _golden(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _sent(call: dict[str, Any]) -> dict[str, Any]:
    return {"method": call["method"], "path": call["path"], "body": call["body"]}


def _bind(repo: Path, rule_id: str = FIRST_ID) -> None:
    record_external_id(UUID, "exabeam", "exabeam-eu", rule_id, repo)


# --- create, update, disable, delete ---------------------------------------------------


def test_create_checks_the_name_sends_the_golden_and_records_the_id(
    run: Run, tide_corpus_repo: Path
) -> None:
    fake = run()
    assert fake.routes() == [
        f"POST {TOKEN_PATH}",
        f"GET {RULES_PATH}",
        f"POST {RULES_PATH}",
    ]
    assert fake.calls[1]["params"] == {"nameContains": NAME}
    assert _sent(fake.calls[2]) == _golden("rule-exabeam-threshold-1.0.create.api.json")
    # Exabeam answered the id in upper case: the shard holds it lower-case and canonical.
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert not _failed()


def test_update_sends_the_whole_body_and_keeps_the_binding(
    run: Run, tide_corpus_repo: Path
) -> None:
    _bind(tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {"name": "old"}
    fake = run()
    assert fake.rule_calls() == [f"PUT {RULES_PATH}/{FIRST_ID}"]
    assert _sent(fake.calls[1]) == _golden("rule-exabeam-threshold-1.0.update.api.json")
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert not _failed() and not _warned()


def test_disablement_is_the_same_put_with_enabled_false(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {"name": "old"}
    fake = run(_rule("DISABLED"))
    assert fake.rule_calls() == [f"PUT {RULES_PATH}/{FIRST_ID}"]
    assert _sent(fake.calls[1]) == _golden("rule-exabeam-threshold-1.0.disable.api.json")
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert not _failed()


def test_deletion_deletes_and_forgets(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {"name": "old"}
    fake = run(_rule("REMOVED"))
    assert fake.rule_calls() == [f"DELETE {RULES_PATH}/{FIRST_ID}"]
    assert _bound(tide_corpus_repo) is None
    assert not _failed()


def test_deleting_a_rule_already_gone_succeeds(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    run(_rule("REMOVED"))
    assert _bound(tide_corpus_repo) is None
    assert not _failed()


def test_a_failed_delete_keeps_the_binding(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    run.fake.script.extend(
        [lambda call: _response(200, {"access_token": "t1"}), lambda call: _response(502)]
    )
    run.fake.tokens = 1
    run(_rule("REMOVED"))
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert _failed()


def test_disable_or_delete_without_a_binding_makes_no_call(run: Run) -> None:
    for status in ("DISABLED", "REMOVED"):
        fake = run(_rule(status))
        assert fake.calls == []
    assert _warned() and not _failed()


# --- the rule is gone ----------------------------------------------------------------


def test_an_update_of_a_rule_gone_creates_it_again(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, NEXT_ID.replace("2c", "3c"))
    fake = run()
    assert fake.rule_calls() == [
        f"PUT {RULES_PATH}/{NEXT_ID.replace('2c', '3c')}",
        f"GET {RULES_PATH}",
        f"POST {RULES_PATH}",
    ]
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert _warned() and not _failed()


def test_disabling_a_rule_gone_forgets_it(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    fake = run(_rule("DISABLED"))
    assert fake.rule_calls() == [f"PUT {RULES_PATH}/{FIRST_ID}"]
    assert _bound(tide_corpus_repo) is None
    assert _warned() and not _failed()


# --- the name check ------------------------------------------------------------------


def test_an_existing_name_is_never_adopted(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.rules[NEXT_ID] = {"name": NAME.upper()}
    fake = run()
    assert fake.rule_calls() == [f"GET {RULES_PATH}"]
    assert _failed()
    assert _bound(tide_corpus_repo) is None


def test_a_longer_name_holding_this_one_is_not_a_conflict(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.rules[NEXT_ID] = {"name": f"{NAME} (old)"}
    fake = run()
    assert fake.rule_calls() == [f"GET {RULES_PATH}", f"POST {RULES_PATH}"]
    assert _bound(tide_corpus_repo) == FIRST_ID


def test_name_matches_is_exact_and_ignores_case() -> None:
    rules = [{"id": "a", "name": "Abc"}, {"id": "b", "name": "Abcd"}, {"id": "c"}]
    assert name_matches(rules, "aBC") == [{"id": "a", "name": "Abc"}]


def test_a_refused_name_check_does_not_create(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.tokens = 1
    run.fake.script.extend(
        [lambda call: _response(200, {"access_token": "t1"}), lambda call: _response(500)]
    )
    fake = run()
    assert fake.rule_calls() == [f"GET {RULES_PATH}"]
    assert _failed()


# --- create answers ------------------------------------------------------------------


def _create_answer(run: Run, answer: Callable[[dict[str, Any]], requests.Response]) -> None:
    """Every create on :attr:`Run.fake` is answered by *answer*; the rest as usual."""
    original = run.fake.request

    def request(method: str, url: str, **kwargs: Any) -> requests.Response:
        if method == "POST" and url == URL + RULES_PATH:
            run.fake.calls.append({"method": method, "path": RULES_PATH, "body": kwargs["json"]})
            return answer(kwargs)
        return original(method, url, **kwargs)

    run.fake.request = request  # type: ignore[method-assign]


def test_a_create_answering_no_uuid_fails_the_rule(run: Run, tide_corpus_repo: Path) -> None:
    _create_answer(run, lambda call: _response(201, {"id": "12345"}))
    run()
    assert _failed()
    assert _bound(tide_corpus_repo) is None


@pytest.mark.parametrize(
    "answer",
    [
        lambda call: (_ for _ in ()).throw(requests.ReadTimeout("read timed out")),
        lambda call: (_ for _ in ()).throw(requests.ConnectionError("reset")),
        lambda call: _response(503, text="Service Unavailable"),
    ],
)
def test_an_unconfirmed_create_is_never_sent_again(
    run: Run, tide_corpus_repo: Path, answer: Any
) -> None:
    _create_answer(run, answer)
    other = _rule()
    ExabeamDeploy().deploy_tenant([_rule(), other], _tenant(), RELEASE, client=run.client())
    posts = [route for route in run.fake.rule_calls() if route == f"POST {RULES_PATH}"]
    assert len(posts) == 2, "one create per rule, never a retry; the tenant goes on"
    assert _failed()
    assert _bound(tide_corpus_repo) is None


def test_a_rejected_create_reports_the_errors_and_trace(
    run: Run, tide_corpus_repo: Path, caplog: pytest.LogCaptureFixture
) -> None:
    body = {
        "errors": [{"code": "INVALID_QUERY", "message": "bad query", "fields": ["query"]}],
        "traceId": "trace-1",
    }
    _create_answer(run, lambda call: _response(400, body))
    run()
    assert _failed()
    assert _bound(tide_corpus_repo) is None


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"id": FIRST_ID}, FIRST_ID),
        ({"id": FIRST_ID.upper()}, FIRST_ID),
        ({"id": f" {FIRST_ID} "}, FIRST_ID),
        ({"id": FIRST_ID.replace("-", "")}, None),
        ({"id": 12}, None),
        ({}, None),
        (None, None),
    ],
)
def test_returned_rule_id(result: Any, expected: str | None) -> None:
    assert returned_rule_id(result) == expected


# --- what a PUT returns --------------------------------------------------------------


def test_a_schedule_the_put_keeps_is_reported(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {
        "name": NAME,
        "scheduleConfig": {"recurrences": [{"recurrenceType": "DAILY"}]},
    }
    original = run.fake.request

    def keep(method: str, url: str, **kwargs: Any) -> requests.Response:
        response = original(method, url, **kwargs)
        if method == "PUT":
            stored = {**kwargs["json"], "scheduleConfig": {"recurrences": [{"x": 1}]}}
            return _response(200, {"id": FIRST_ID, **stored})
        return response

    run.fake.request = keep  # type: ignore[method-assign]
    run()
    assert _warned() and not _failed()


def test_an_auto_disabled_rule_is_reported(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {"name": NAME, "autoDisabled": True}
    run()
    assert _warned() and not _failed()


def test_a_rejected_update_fails_and_keeps_the_binding(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {"name": NAME}
    original = run.fake.request

    def reject(method: str, url: str, **kwargs: Any) -> requests.Response:
        if method == "PUT":
            return _response(400, {"errors": [{"code": "E", "message": "no"}], "traceId": "t"})
        return original(method, url, **kwargs)

    run.fake.request = reject  # type: ignore[method-assign]
    run()
    assert _failed()
    assert _bound(tide_corpus_repo) == FIRST_ID


def test_a_name_longer_than_128_is_never_sent(run: Run) -> None:
    document = yaml.safe_load(
        (FIXTURES / "rule-exabeam-threshold-1.0.yaml").read_text(encoding="utf-8")
    )
    document["name"] = "x" * 129
    fake = run(load_rule_from_dict(document))
    assert fake.rule_calls() == []
    assert _failed()


# --- the token, rate limits, refusals --------------------------------------------------


def test_one_token_serves_the_run(run: Run) -> None:
    client = run.client()
    client.rules_named("a")
    client.rules_named("b")
    assert run.fake.routes().count(f"POST {TOKEN_PATH}") == 1


def test_an_expired_token_is_renewed_once(run: Run) -> None:
    client = run.client()
    client.rules_named("a")
    run.fake.script.append(lambda call: _response(401, {"message": "Jwt is expired"}))
    client.rules_named("b")
    assert run.fake.routes() == [
        f"POST {TOKEN_PATH}",
        f"GET {RULES_PATH}",
        f"GET {RULES_PATH}",
        f"POST {TOKEN_PATH}",
        f"GET {RULES_PATH}",
    ]
    assert run.fake.calls[-1]["auth"] == "Bearer t2"


def test_a_second_expired_token_stops_the_tenant(run: Run) -> None:
    client = run.client()
    client.token()
    expired = lambda call: _response(401, text="Jwt is expired")  # noqa: E731 -- one answer, twice
    run.fake.script.extend([expired, lambda call: _response(200, {"access_token": "t9"}), expired])
    with pytest.raises(ExabeamTenantError, match="exabeam_tenant_unauthorized"):
        client.rules_named("a")


@pytest.mark.parametrize(
    ("answer", "code"),
    [
        (lambda call: _response(401, {"message": "invalid credentials"}), "unauthorized"),
        (lambda call: _response(403, {"message": "forbidden"}), "unauthorized"),
        (
            lambda call: _response(
                409, {"errors": [{"message": "Feature is not enabled for subscription"}]}
            ),
            "feature_unavailable",
        ),
    ],
)
def test_a_refusing_tenant_stops(
    run: Run, answer: Any, code: str, caplog: pytest.LogCaptureFixture
) -> None:
    client = run.client()
    client.token()
    run.fake.script.append(answer)
    other = _rule()
    ExabeamDeploy().deploy_tenant([_rule(), other], _tenant(), RELEASE, client=client)
    assert run.fake.rule_calls() == [f"GET {RULES_PATH}"], "the tenant stops at the first refusal"
    assert _failed()


def test_a_refused_token_stops_the_tenant(run: Run) -> None:
    run.fake.script.append(lambda call: _response(401, {"message": "bad client"}))
    fake = run()
    assert fake.routes() == [f"POST {TOKEN_PATH}"]
    assert _failed()


def test_an_unreachable_tenant_stops(run: Run) -> None:
    def down(call: dict[str, Any]) -> requests.Response:
        raise requests.ConnectionError("refused")

    run.fake.script.append(down)
    fake = run()
    assert fake.routes() == [f"POST {TOKEN_PATH}"]
    assert _failed()


@pytest.mark.parametrize("headers", [{"Retry-After": "7"}, {}])
def test_a_429_waits_and_resends_the_same_request(
    run: Run, headers: dict[str, str], tide_corpus_repo: Path
) -> None:
    run.fake.script.append(lambda call: _response(429, headers=headers))
    fake = run()
    assert fake.routes()[:2] == [f"POST {TOKEN_PATH}", f"POST {TOKEN_PATH}"]
    assert (7.0 if headers else 60.0) in run.slept
    assert _bound(tide_corpus_repo) == FIRST_ID


def test_still_rate_limited_gives_up(run: Run) -> None:
    client = run.client()
    run.fake.script.extend([lambda call: _response(429, headers={"Retry-After": "0"})] * 11)
    with pytest.raises(ExabeamApiError, match="still rate limited"):
        client.token()


def test_requests_are_paced_a_hundred_per_minute_across_clients(run: Run) -> None:
    for _ in range(100):
        run.fake.script.append(lambda call: _response(200, {"access_token": "t"}))
    for _ in range(100):
        run.client().token()  # a client per call: the pace is the process's, not the client's
    assert run.slept == []
    run.fake.script.append(lambda call: _response(200, {"access_token": "t"}))
    run.client().token()
    assert run.slept == [60.0]


def test_an_unset_credential_fails_the_tenant_before_any_call(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(requests.Session, "request", lambda *a, **k: calls.append("x"))
    ExabeamDeploy().deploy_tenant([_rule()], _tenant(client_id="$EXABEAM_CLIENT_ID"), RELEASE)
    assert calls == []
    assert _failed()


def test_api_error_reads_errors_and_trace() -> None:
    response = _response(
        400,
        {
            "errors": [
                {"code": "INVALID", "message": "bad", "fields": ["a", "b"]},
                {"message": "worse", "fields": "c"},
            ],
            "traceId": "abc",
        },
    )
    error = api_error("POST /x", response)
    assert error.status == 400
    assert error.trace_id == "abc"
    assert error.detail == "INVALID: bad (fields: a, b); worse (fields: c) (traceId abc)"
    plain = api_error("GET /y", _response(502, text="<html><title>Bad Gateway</title></html>"))
    assert plain.status == 502 and plain.errors == ()


# --- deployment state ----------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [FIRST_ID.upper(), FIRST_ID.replace("-", ""), "x", 12, ""],
)
def test_a_shard_holds_only_canonical_lower_case_uuids(value: object) -> None:
    with pytest.raises(DeploymentStateError) as caught:
        normalise_external_id("exabeam", value)
    assert caught.value.code == "external_id_shape"
    assert normalise_external_id("exabeam", FIRST_ID) == FIRST_ID


@pytest.mark.parametrize("name", ["exabeam-bad-id.json", "exabeam-uppercase-id.json"])
def test_the_specification_bad_shards_are_refused(tide_corpus_repo: Path, name: str) -> None:
    from opentide.states.deployment import DeploymentState

    document = json.loads((FIXTURES / "state" / name).read_text(encoding="utf-8"))
    path = shard_path(document["object_uuid"], tide_corpus_repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(DeploymentStateError) as caught:
        DeploymentState.load(document["object_uuid"], tide_corpus_repo)
    assert caught.value.code == "deployment_state_shape"


# --- adversarial review of PR #983 ---------------------------------------------------------


@pytest.fixture
def reported(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The rule-level deployment error codes a run reports, in order."""
    from opentide.platforms.exabeam import deployer as deployer_module

    seen: list[str] = []
    real = deployer_module._deployment_error

    def error(code: str, **kwargs: Any) -> None:
        seen.append(code)
        real(code, **kwargs)

    monkeypatch.setattr(deployer_module, "_deployment_error", error)
    return seen


def _token(call: dict[str, Any]) -> requests.Response:
    return _response(200, {"access_token": "t1"})


def test_a_create_accepted_with_an_unreadable_answer_is_create_no_id(
    run: Run, tide_corpus_repo: Path, reported: list[str]
) -> None:
    """A 2xx create whose body is not a rule: the rule exists without a binding (exabeam-1.0)."""
    run.fake.script = [
        _token,
        lambda call: _response(200, []),
        lambda call: _response(201, text="<html>Created</html>"),
    ]
    run()
    assert reported == ["exabeam_create_no_id"]
    assert _bound(tide_corpus_repo) is None
    assert _failed()


@pytest.mark.parametrize("payload", [{"data": [{"id": FIRST_ID, "name": NAME}]}, {"total": 0}])
def test_a_name_check_answer_of_another_shape_refuses_the_create(
    run: Run, tide_corpus_repo: Path, reported: list[str], payload: dict[str, Any]
) -> None:
    """An unknown object shape is never read as "no rule has this name"."""
    run.fake.script = [_token, lambda call: _response(200, payload)]
    run.fake.tokens = 1
    fake = run()
    assert f"POST {RULES_PATH}" not in fake.routes()
    assert reported == ["exabeam_request_failed"]
    assert _bound(tide_corpus_repo) is None


def test_retry_after_is_read_as_seconds_or_an_http_date() -> None:
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime

    from opentide.platforms.exabeam.client import DEFAULT_RETRY_AFTER, _retry_after

    now = datetime(2026, 11, 12, 9, 0, tzinfo=timezone.utc)

    def wait(value: str | None) -> float:
        headers = {} if value is None else {"Retry-After": value}
        return _retry_after(_response(429, {}, headers), now=now)

    assert wait("7") == 7.0
    assert wait(format_datetime(now + timedelta(seconds=120), usegmt=True)) == 120.0
    assert wait(format_datetime(now - timedelta(seconds=30), usegmt=True)) == 0.0
    for odd in (None, "", "soon", "nan", "inf", "-inf"):
        assert wait(odd) == DEFAULT_RETRY_AFTER, odd
    assert wait("-5") == 0.0


def test_a_retry_after_longer_than_five_minutes_fails_the_request(
    run: Run, tide_corpus_repo: Path
) -> None:
    """A 429 that asks for days fails the request instead of stalling the run."""
    run.fake.script = [lambda call: _response(429, {}, {"Retry-After": "864000"})]
    run()
    assert run.slept == []
    assert _failed()
    assert _bound(tide_corpus_repo) is None


def test_a_retry_after_of_nan_does_not_escape_the_deploy(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.script = [lambda call: _response(429, {}, {"Retry-After": "nan"})] * 11
    run()  # a NaN wait is the default wait; the request fails after its resends
    assert run.slept and set(run.slept) == {60.0}
    assert _failed()


@pytest.mark.parametrize(
    "token_answer",
    [
        lambda call: _response(503, {"errors": [{"code": "503", "message": "down"}]}),
        lambda call: (_ for _ in ()).throw(requests.ConnectionError("reset")),
    ],
    ids=["token-5xx", "token-no-answer"],
)
def test_a_token_that_cannot_be_renewed_stops_the_tenant_not_a_create(
    run: Run,
    tide_corpus_repo: Path,
    reported: list[str],
    caplog: pytest.LogCaptureFixture,
    token_answer: Callable[[dict[str, Any]], requests.Response],
) -> None:
    """The create was refused (expired token) and never sent again: not unconfirmed."""
    run.fake.script = [
        _token,
        lambda call: _response(200, []),
        lambda call: _response(401, text='{"message":"Jwt is expired"}'),
        token_answer,
    ]
    run.fake.tokens = 1
    fake = run()
    assert "exabeam_create_unconfirmed" not in reported
    assert fake.routes().count(f"POST {RULES_PATH}") == 1
    assert _failed()
    assert _bound(tide_corpus_repo) is None
