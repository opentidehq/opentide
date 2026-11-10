"""Bitdefender deploy: GravityZone JSON-RPC with deployment state (bitdefender-1.0).

The HTTP boundary is a fake ``requests`` session that records every call and
answers like the GravityZone Incidents API, errors in HTTP 200 included.
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
from opentide.platforms.bitdefender import client as client_module
from opentide.platforms.bitdefender.client import (
    API_PATH,
    PACER,
    BitdefenderApiError,
    BitdefenderClient,
    is_name_conflict,
    pace_key,
)
from opentide.platforms.bitdefender.deployer import BitdefenderDeploy, returned_rule_id
from opentide.states.deployment import (
    DeploymentStateError,
    normalise_external_id,
    record_external_id,
    shard_path,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bitdefender"
UUID = "00000000-0000-4000-8003-000000000051"
RELEASE = (StatusStrategy.RELEASE,)
Tenant = ConfigurationModels.Systems.Bitdefender.Tenant
URL = "https://cloudgz.gravityzone.example/api"
FIRST_ID = "6372b7a3897aaa77ee021642"
NEXT_ID = "6372b7a3897aaa77ee021643"


def _response(
    status: int, body: Any = None, headers: dict[str, str] | None = None
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = b"" if body is None else json.dumps(body).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    response.headers.update(headers or {})
    return response


def _error(request_id: str, code: int, message: str, details: str | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["data"] = {"details": details}
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


class FakeGravityZone:
    """Custom rules, answered as the Incidents API answers them."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.rules: dict[str, dict[str, Any]] = {}
        self.ids = iter([FIRST_ID, NEXT_ID, "6372b7a3897aaa77ee021644"])
        #: Answers queued ahead of the normal behaviour, each a callable of the body.
        self.script: list[Callable[[dict[str, Any]], requests.Response]] = []
        self.auth: Any = None
        self.headers: dict[str, str] = {}

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        assert url == URL + API_PATH
        assert kwargs.get("timeout"), "every request has a timeout"
        body = kwargs["json"]
        assert body["jsonrpc"] == "2.0" and isinstance(body["id"], str) and body["id"]
        self.calls.append(body)
        if self.script:
            return self.script.pop(0)(body)
        method, params, request_id = body["method"], body["params"], body["id"]
        assert params["type"] == 1, "never an exclusion rule"
        if method == "createCustomRule":
            assert params["returnRuleId"] is True
            if any(rule["name"] == params["name"] for rule in self.rules.values()):
                return _response(
                    200,
                    _error(
                        request_id, -32602, "Invalid params", "A rule with this name already exists"
                    ),
                )
            rule_id = next(self.ids)
            self.rules[rule_id] = params
            return _response(200, {"jsonrpc": "2.0", "id": request_id, "result": rule_id})
        if method in ("updateCustomRule", "deleteCustomRule"):
            if params["ruleId"] not in self.rules:
                return _response(200, _error(request_id, -32002, "Resource not found"))
            if method == "deleteCustomRule":
                del self.rules[params["ruleId"]]
            else:
                self.rules[params["ruleId"]] = params
            return _response(200, {"jsonrpc": "2.0", "id": request_id, "result": True})
        raise AssertionError(f"unexpected method {method}")

    def methods(self) -> list[str]:
        return [call["method"] for call in self.calls]


@pytest.fixture(autouse=True)
def _deployment_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    PACER.reset()


def _tenant(**setup: Any) -> Any:
    values = {field.name: None for field in dataclasses.fields(Tenant.Setup)} | {
        "ssl": True,
        "url": URL,
        "api_key": "key",
        "key_type": "personal",
        "automatic_actions": True,
        "tags": ["managed-by-opentide"],
        "endpoint_tags": {
            "tier0-servers": {
                "tag_id": "5b680f6fb1a43d860a7b23c8",
                "company_id": "61827b8036492c2fc0718722",
            }
        },
    }
    return Tenant(name="gravityzone-eu", description="", setup=Tenant.Setup(**(values | setup)))


def _rule(
    status: str = "STAGING", name: str = "rule-bitdefender-detection-1.0.yaml"
) -> DetectionRule:
    document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    document["configurations"]["bitdefender"]["status"] = status
    return load_rule_from_dict(document)


class Run:
    """Deploy one rule to one tenant against :attr:`fake`, with no real sleeps."""

    def __init__(self) -> None:
        self.fake = FakeGravityZone()
        self.slept: list[float] = []
        self.now = 0.0

    def client(self, **kwargs: Any) -> BitdefenderClient:
        def sleep(seconds: float) -> None:
            self.slept.append(seconds)
            self.now += seconds

        built = BitdefenderClient(
            URL, "key", tenant="gravityzone-eu", sleep=sleep, clock=lambda: self.now, **kwargs
        )
        self.fake.auth = built.session.auth
        self.fake.headers = dict(built.session.headers)
        built.session.post = self.fake.post  # type: ignore[method-assign]
        return built

    def __call__(
        self, rule: DetectionRule | None = None, tenant: Any = None, strategies: Any = RELEASE
    ) -> FakeGravityZone:
        BitdefenderDeploy().deploy_tenant(
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


def _shard(repo: Path) -> dict[str, Any] | None:
    path = shard_path(UUID, repo)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _bound(repo: Path) -> str | None:
    shard = _shard(repo)
    return (shard or {}).get("platforms", {}).get("bitdefender", {}).get("gravityzone-eu")


def _failed() -> bool:
    return bool(os.environ.get("DEPLOYMENT_ERROR_RAISED"))


def _warned() -> bool:
    return bool(os.environ.get("DEPLOYMENT_WARNING_RAISED"))


def _golden(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _without_id(call: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in call.items() if key != "id"}


# --- create, update, disable, delete ---------------------------------------------------


def test_create_sends_the_golden_and_records_the_id(run: Run, tide_corpus_repo: Path) -> None:
    fake = run()
    assert fake.methods() == ["createCustomRule"]
    assert _without_id(fake.calls[0]) == _golden("rule-bitdefender-detection-1.0.create.api.json")
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert not _failed()


def test_update_sends_the_whole_payload_and_keeps_the_binding(
    run: Run, tide_corpus_repo: Path
) -> None:
    record_external_id(UUID, "bitdefender", "gravityzone-eu", FIRST_ID, tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {"name": "old"}
    fake = run()
    assert fake.methods() == ["updateCustomRule"]
    assert _without_id(fake.calls[0]) == _golden("rule-bitdefender-detection-1.0.update.api.json")
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert not _failed()


def test_disablement_is_an_update_with_status_zero(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID, "bitdefender", "gravityzone-eu", FIRST_ID, tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {"name": "old"}
    fake = run(_rule("DISABLED"))
    assert _without_id(fake.calls[0]) == _golden("rule-bitdefender-detection-1.0.disable.api.json")
    assert _bound(tide_corpus_repo) == FIRST_ID


def test_deletion_deletes_and_forgets(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID, "bitdefender", "gravityzone-eu", FIRST_ID, tide_corpus_repo)
    run.fake.rules[FIRST_ID] = {"name": "old"}
    fake = run(_rule("REMOVED"))
    assert fake.calls[0]["method"] == "deleteCustomRule"
    assert fake.calls[0]["params"] == {"ruleId": FIRST_ID, "type": 1}
    assert _bound(tide_corpus_repo) is None
    assert not _failed()


def test_deleting_a_rule_already_gone_succeeds(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID, "bitdefender", "gravityzone-eu", FIRST_ID, tide_corpus_repo)
    run(_rule("REMOVED"))
    assert _bound(tide_corpus_repo) is None
    assert not _failed()


def test_disable_or_delete_without_a_binding_makes_no_call(run: Run) -> None:
    for status in ("DISABLED", "REMOVED"):
        fake = run(_rule(status))
        assert fake.calls == []
    assert _warned() and not _failed()


# --- the rule is gone ----------------------------------------------------------------


def test_an_update_of_a_rule_gone_creates_it_again(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID, "bitdefender", "gravityzone-eu", "0" * 24, tide_corpus_repo)
    fake = run()
    assert fake.methods() == ["updateCustomRule", "createCustomRule"]
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert _warned() and not _failed()


def test_disabling_a_rule_gone_forgets_it(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID, "bitdefender", "gravityzone-eu", "0" * 24, tide_corpus_repo)
    fake = run(_rule("DISABLED"))
    assert fake.methods() == ["updateCustomRule"]
    assert _bound(tide_corpus_repo) is None
    assert _warned() and not _failed()


# --- create answers ------------------------------------------------------------------


def test_a_create_answering_no_id_fails_the_rule(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.script.append(
        lambda body: _response(200, {"jsonrpc": "2.0", "id": body["id"], "result": True})
    )
    run()
    assert _failed()
    assert _bound(tide_corpus_repo) is None


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (FIRST_ID, FIRST_ID),
        (FIRST_ID.upper(), FIRST_ID),
        ({"ruleId": FIRST_ID}, FIRST_ID),
        (True, None),
        ("123", None),
        (None, None),
    ],
)
def test_returned_rule_id(result: Any, expected: str | None) -> None:
    assert returned_rule_id(result) == expected


def test_a_name_conflict_is_not_adopted(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.rules["0" * 24] = {"name": "Office application spawns encoded PowerShell"}
    fake = run()
    assert fake.methods() == ["createCustomRule"]
    assert _failed()
    assert _bound(tide_corpus_repo) is None


def test_a_create_with_no_answer_is_retried_once(run: Run, tide_corpus_repo: Path) -> None:
    def reset(body: dict[str, Any]) -> requests.Response:
        raise requests.ConnectionError("connection reset")

    run.fake.script.append(reset)
    fake = run()
    assert fake.methods() == ["createCustomRule", "createCustomRule"]
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert not _failed()


def test_a_name_conflict_on_the_retry_is_unconfirmed(
    run: Run, tide_corpus_repo: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def created_then_lost(body: dict[str, Any]) -> requests.Response:
        run.fake.rules["0" * 24] = body["params"]
        raise requests.Timeout("read timed out")

    run.fake.script.append(created_then_lost)
    fake = run()
    assert fake.methods() == ["createCustomRule", "createCustomRule"]
    assert _failed()
    assert _bound(tide_corpus_repo) is None


# --- errors, rate limits, auth -------------------------------------------------------


def test_an_error_in_http_200_fails_the_rule(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.script.append(
        lambda body: _response(200, _error(body["id"], -32000, "Server error", "boom"))
    )
    run()
    assert _failed()
    assert _bound(tide_corpus_repo) is None


def test_a_kind_change_fails_the_update(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID, "bitdefender", "gravityzone-eu", FIRST_ID, tide_corpus_repo)
    run.fake.script.append(
        lambda body: _response(
            200, _error(body["id"], -32602, "Invalid params", "Rule type mismatch")
        )
    )
    run()
    assert _failed()
    assert _bound(tide_corpus_repo) == FIRST_ID


@pytest.mark.parametrize(
    "answer",
    [
        lambda body: _response(200, _error(body["id"], -32001, "API Key is not allowed")),
        lambda body: _response(401),
        lambda body: _response(403, {"message": "forbidden"}),
        lambda body: _response(200, _error(body["id"], -32601, "Method not found")),
    ],
)
def test_an_unauthorized_tenant_stops(run: Run, answer: Any, tide_corpus_repo: Path) -> None:
    run.fake.script.append(answer)
    other = _rule()
    BitdefenderDeploy().deploy_tenant([_rule(), other], _tenant(), RELEASE, client=run.client())
    assert len(run.fake.calls) == 1, "the tenant stops at the first refusal"
    assert _failed()


@pytest.mark.parametrize(
    "limited",
    [
        lambda body: _response(429, headers={"Retry-After": "7"}),
        lambda body: _response(
            429, _error(body["id"], -32003, "Too many requests"), {"Retry-After": "7"}
        ),
        lambda body: _response(
            200, _error(body["id"], -32003, "Too many requests"), {"Retry-After": "7"}
        ),
    ],
)
def test_a_rate_limit_waits_and_resends_the_same_request(
    run: Run, limited: Any, tide_corpus_repo: Path
) -> None:
    run.fake.script.append(limited)
    fake = run()
    assert fake.methods() == ["createCustomRule", "createCustomRule"]
    assert fake.calls[0] == fake.calls[1]
    assert 7.0 in run.slept
    assert _bound(tide_corpus_repo) == FIRST_ID


def test_creates_and_deletes_are_paced_five_per_minute(run: Run) -> None:
    client = run.client()
    for index in range(6):
        run.fake.rules[f"{index:024x}"] = {"name": str(index)}
    for index in range(6):
        client.delete_rule({"ruleId": f"{index:024x}", "type": 1})
    assert run.slept == [60.0]
    run.slept.clear()
    run.fake.rules["0" * 24] = {"name": "kept"}
    client.update_rule({"ruleId": "0" * 24, "type": 1, "name": "u"})
    assert run.slept == []


def test_the_pace_is_shared_by_clients_of_one_key(run: Run) -> None:
    for _ in range(5):
        run.fake.script.append(
            lambda body: _response(200, {"jsonrpc": "2.0", "id": body["id"], "result": True})
        )
        run.client().delete_rule({"ruleId": "0" * 24, "type": 1})
    run.fake.script.append(
        lambda body: _response(200, {"jsonrpc": "2.0", "id": body["id"], "result": True})
    )
    run.client().delete_rule({"ruleId": "0" * 24, "type": 1})
    assert run.slept == [60.0]


def test_personal_and_service_keys(run: Run) -> None:
    run.client()
    assert run.fake.auth == ("key", "")
    assert "X-API-Key" not in run.fake.headers
    run.client(key_type="service")
    assert run.fake.auth is None
    assert run.fake.headers["X-API-Key"] == "key"


@pytest.mark.parametrize(
    ("details", "conflict"),
    [
        ("A rule with this name already exists", True),
        ("Duplicate rule name", True),
        ("The rule name must be unique", True),
        ("The name is already in use", True),
        (None, False),
        ("", False),
        ("Invalid value for parameter severity", False),
        ("Duplicate value in criteriaList", False),
        ("The tag already exists", False),
        ("Invalid value for parameter name", False),
    ],
)
def test_name_conflicts_are_read_from_the_error_details(
    details: str | None, conflict: bool
) -> None:
    assert is_name_conflict(details) is conflict
    error = BitdefenderApiError("createCustomRule", -32602, "Invalid params", details)
    assert error.name_conflict is conflict
    # Only the details carry the conflict: the message alone never does.
    assert not BitdefenderApiError("createCustomRule", -32602, "name already exists").name_conflict
    # Only a create can conflict on its name.
    assert not BitdefenderApiError("updateCustomRule", -32602, "x", details).name_conflict


def test_api_error_text_carries_the_details() -> None:
    error = BitdefenderApiError("createCustomRule", -32602, "Invalid params", "name already exists")
    assert error.name_conflict
    assert "name already exists" in str(error)
    assert not BitdefenderApiError("updateCustomRule", -32000, "Server error").type_mismatch


def test_unknown_target_alias_fails_before_any_call(run: Run, tide_corpus_repo: Path) -> None:
    fake = run(tenant=_tenant(endpoint_tags={}))
    assert fake.calls == []
    assert _failed()


def test_tenant_without_automatic_actions_warns_and_omits_them(run: Run) -> None:
    fake = run(tenant=_tenant(automatic_actions=False))
    assert "automaticActions" not in fake.calls[0]["params"]["settings"]
    assert _warned()


def test_deploy_never_lists_rules(run: Run, tide_corpus_repo: Path) -> None:
    run()
    record_external_id(UUID, "bitdefender", "gravityzone-eu", FIRST_ID, tide_corpus_repo)
    run()
    run(_rule("REMOVED"))
    assert "getCustomRulesList" not in run.fake.methods()


def test_the_client_has_no_transport_retry() -> None:
    built = BitdefenderClient(URL, "key", tenant="t")
    assert built.session.get_adapter("https://x").max_retries.total == 0


def test_rate_limit_that_never_clears_fails() -> None:
    built = BitdefenderClient(URL, "key", tenant="t", sleep=lambda _s: None)
    built.session.post = lambda url, **kwargs: _response(429)  # type: ignore[method-assign]
    with pytest.raises(BitdefenderApiError, match="still rate limited"):
        built.update_rule({"ruleId": "0" * 24})
    assert client_module.MAX_RATE_LIMITED == 10


# --- deployment state ----------------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["6372B7A3897AAA77EE021642", "123", 123, "6372b7a3897aaa77ee02164"]
)
def test_bitdefender_ids_are_24_lower_case_hex(value: Any) -> None:
    with pytest.raises(DeploymentStateError, match="external_id_shape"):
        normalise_external_id("bitdefender", value)
    assert normalise_external_id("bitdefender", FIRST_ID) == FIRST_ID


def test_a_create_cut_off_mid_answer_is_retried_once(run: Run, tide_corpus_repo: Path) -> None:
    def truncated(body: dict[str, Any]) -> requests.Response:
        raise requests.exceptions.ChunkedEncodingError("connection broken: incomplete read")

    run.fake.script.append(truncated)
    fake = run()
    assert fake.methods() == ["createCustomRule", "createCustomRule"]
    assert _bound(tide_corpus_repo) == FIRST_ID
    assert not _failed()


def test_two_creates_without_an_answer_fail_that_rule_only(
    run: Run, tide_corpus_repo: Path
) -> None:
    def lost(body: dict[str, Any]) -> requests.Response:
        raise requests.Timeout("read timed out")

    run.fake.script.extend([lost, lost])
    other = _rule(name="rule-bitdefender-yara-1.0.yaml")
    BitdefenderDeploy().deploy_tenant([_rule(), other], _tenant(), RELEASE, client=run.client())
    # The first rule is unconfirmed; the tenant goes on to the second.
    assert run.fake.methods() == ["createCustomRule"] * 3
    assert _bound(tide_corpus_repo) is None
    assert _failed()


def test_an_unset_api_key_variable_is_refused_before_any_call(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GRAVITYZONE_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GRAVITYZONE_API_KEY"):
        BitdefenderClient(URL, "$GRAVITYZONE_API_KEY", tenant="t")
    posted: list[Any] = []
    monkeypatch.setattr(requests.Session, "post", lambda *a, **k: posted.append(a))
    BitdefenderDeploy().deploy_tenant([_rule()], _tenant(api_key="$GRAVITYZONE_API_KEY"), RELEASE)
    assert posted == []
    assert _failed()


def test_the_pacer_never_holds_the_key() -> None:
    assert pace_key("secret") == pace_key("secret")
    assert pace_key("secret") != pace_key("other")
    assert "secret" not in pace_key("secret")
    client = BitdefenderClient(URL, "secret", tenant="t")
    assert client._pace_key == pace_key("secret")
