"""Sysdig deploy: the Secure API with deployment state, and Falco rules files (sysdig-1.0).

The HTTP boundary is a fake ``requests`` session that records every call and
answers like the Sysdig Secure runtime API. Everything above it is real: the
deployer, the compiler, the deployment-state planner and shard writes.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import requests
from tests.corpus_support import CORPUS_RULE_UUIDS, clear_runtime_caches

from opentide.models.deployment_enums import StatusStrategy
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.sysdig import deployer as module
from opentide.platforms.sysdig.client import SysdigClient, SysdigTenantError
from opentide.states.deployment import record_external_id, shard_path

UUID = CORPUS_RULE_UUIDS["sysdig"]
RELEASE = (StatusStrategy.RELEASE,)
Tenant = ConfigurationModels.Systems.Sysdig.Tenant
POLICY = "opentide managed detections"
RULE_NAME = "Sysdig Falco Rule"


def _response(status: int, body: Any = None) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = b"" if body is None else json.dumps(body).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


class FakeSysdig:
    """Rules and policies, answered as Sysdig answers them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.rules: dict[int, dict[str, Any]] = {}
        self.policies: list[dict[str, Any]] = [
            {"id": 7, "name": POLICY, "ruleNames": ["Other rule"], "type": "falco", "version": 2}
        ]
        self.next_id = 42
        self.status_override: int | None = None

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        path = url.split("://", 1)[1].split("/", 1)[1]
        body = kwargs.get("json")
        self.calls.append((method, "/" + path, body))
        assert kwargs.get("timeout"), "every request has a timeout"
        if self.status_override is not None:
            return _response(self.status_override, {"message": "denied"})
        parts = path.split("/")
        if path == "api/secure/rules" and method == "POST":
            rule = {**body, "id": self.next_id, "version": 1}
            self.rules[self.next_id] = rule
            self.next_id += 1
            return _response(201, rule)
        if path.startswith("api/secure/rules/"):
            rule_id = int(parts[-1])
            if rule_id not in self.rules:
                return _response(404, {"message": "not found"})
            if method == "GET":
                return _response(200, self.rules[rule_id])
            if method == "PUT":
                assert body["version"] == self.rules[rule_id]["version"]
                self.rules[rule_id] = {**body, "version": body["version"] + 1}
                return _response(200, self.rules[rule_id])
            if method == "DELETE":
                del self.rules[rule_id]
                return _response(204)
        if path == "api/v2/policies" and method == "GET":
            return _response(200, self.policies)
        if path.startswith("api/v2/policies/") and method == "PUT":
            policy_id = int(parts[-1])
            for index, policy in enumerate(self.policies):
                if policy["id"] == policy_id:
                    self.policies[index] = body
            return _response(200, body)
        raise AssertionError(f"unexpected {method} {url}")

    def methods(self) -> list[tuple[str, str]]:
        return [(method, path) for method, path, _ in self.calls]

    def policy_rules(self) -> list[str]:
        return list(self.policies[0]["ruleNames"])


@pytest.fixture(autouse=True)
def _deployment_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


def _tenant(**setup: Any) -> Any:
    values = {field.name: None for field in dataclasses.fields(Tenant.Setup)} | {
        "ssl": True,
        "delivery": "api",
        "url": "https://eu1.app.sysdig.example",
        "api_token": "token",
        "policies": [POLICY],
        "rules_dir": "",
        "tags": None,
    }
    return Tenant(name="staging", description="", setup=Tenant.Setup(**(values | setup)))


def _set_status(repo: Path, status: str, extra: str = "") -> None:
    path = repo / "objects" / "rules" / "rule-0013-sysdig-falco.yaml"
    text = path.read_text(encoding="utf-8").replace("    status: STAGING", f"    status: {status}")
    if extra:
        text = text.replace(
            "    tags: [container, shell]\n", f"    tags: [container, shell]\n{extra}"
        )
    path.write_text(text, encoding="utf-8")
    clear_runtime_caches()


class SysdigRun:
    """Deploy the corpus Sysdig rule to one tenant, against :attr:`fake`."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.fake = FakeSysdig()
        self._monkeypatch = monkeypatch

        def client(*args: Any, **kwargs: Any) -> SysdigClient:
            built = SysdigClient(*args, **kwargs)
            monkeypatch.setattr(built.session, "request", self.fake.request)
            return built

        monkeypatch.setattr(module, "SysdigClient", client)

    def __call__(self, tenant: Any = None, strategies: Any = RELEASE) -> FakeSysdig:
        chosen = tenant or _tenant()

        def tide_deployment(deployment: list[Any], system: Any, strategies: Any) -> Any:
            del system, strategies
            return SimpleNamespace(
                rule_deployment=[SimpleNamespace(tenant=chosen, rules=deployment)]
            )

        self._monkeypatch.setattr(module, "TideDeployment", tide_deployment)
        module.SysdigDeploy().deploy([UUID], strategies)
        return self.fake


@pytest.fixture
def sysdig(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> SysdigRun:
    del tide_corpus_repo
    return SysdigRun(monkeypatch)


def _shard(repo: Path) -> dict[str, Any] | None:
    path = shard_path(UUID, repo)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _failed() -> bool:
    return bool(os.environ.get("DEPLOYMENT_ERROR_RAISED"))


def _warned() -> bool:
    return bool(os.environ.get("DEPLOYMENT_WARNING_RAISED"))


# --- api: create, update, recreate ------------------------------------------------


def test_create_records_the_id_and_joins_the_policy(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    fake = sysdig()
    assert fake.methods() == [
        ("POST", "/api/secure/rules"),
        ("GET", "/api/v2/policies"),
        ("PUT", "/api/v2/policies/7"),
    ]
    body = fake.calls[0][2]
    assert body["name"] == RULE_NAME
    assert body["details"]["condition"]["condition"] == (
        "spawned_process and container and proc.name in (bash, sh, zsh)"
    )
    assert _shard(tide_corpus_repo) == {
        "object_uuid": UUID,
        "platforms": {"sysdig": {"staging": "42"}},
        "schema": "deployment.state::1.0",
    }
    assert fake.policy_rules() == ["Other rule", RULE_NAME]
    assert not _failed()


def test_bearer_token_and_tls_are_the_tenants(tide_corpus_repo: Path) -> None:
    client = SysdigClient("https://x.example/", "secret", tenant="t", verify_ssl=False)
    assert client.session.headers["Authorization"] == "Bearer secret"
    assert client.session.verify is False
    assert client.url == "https://x.example"


def test_update_sends_the_remote_version_and_keeps_the_binding(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    record_external_id(UUID, "sysdig", "staging", "42", tide_corpus_repo)
    fake = sysdig.fake
    fake.rules[42] = {"id": 42, "name": RULE_NAME, "version": 5}
    fake.policies[0]["ruleNames"] = [RULE_NAME]
    sysdig()
    assert fake.methods() == [
        ("GET", "/api/secure/rules/42"),
        ("PUT", "/api/secure/rules/42"),
        ("GET", "/api/v2/policies"),
    ]
    put = fake.calls[1][2]
    assert (put["id"], put["version"]) == (42, 5)
    assert _shard(tide_corpus_repo)["platforms"] == {"sysdig": {"staging": "42"}}


def test_a_renamed_rule_is_renamed_in_its_policies(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    record_external_id(UUID, "sysdig", "staging", "42", tide_corpus_repo)
    fake = sysdig.fake
    fake.rules[42] = {"id": 42, "name": "Old name", "version": 1}
    fake.policies[0]["ruleNames"] = ["Old name", "Other rule"]
    sysdig()
    assert fake.policy_rules() == [RULE_NAME, "Other rule"]


def test_a_rule_gone_from_sysdig_is_created_again(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    record_external_id(UUID, "sysdig", "staging", "9", tide_corpus_repo)
    fake = sysdig()
    assert fake.methods()[:2] == [("GET", "/api/secure/rules/9"), ("POST", "/api/secure/rules")]
    assert _shard(tide_corpus_repo)["platforms"] == {"sysdig": {"staging": "42"}}
    assert _warned()
    assert not _failed()


# --- api: disable, delete -----------------------------------------------------------


def test_disablement_updates_then_leaves_the_policy(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    _set_status(tide_corpus_repo, "DISABLED")
    record_external_id(UUID, "sysdig", "staging", "42", tide_corpus_repo)
    fake = sysdig.fake
    fake.rules[42] = {"id": 42, "name": RULE_NAME, "version": 1}
    fake.policies[0]["ruleNames"] = [RULE_NAME, "Other rule"]
    sysdig()
    assert ("PUT", "/api/secure/rules/42") in fake.methods()
    assert fake.policy_rules() == ["Other rule"]
    assert 42 in fake.rules
    assert _shard(tide_corpus_repo) is not None


def test_deletion_leaves_the_policy_deletes_and_forgets(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    _set_status(tide_corpus_repo, "REMOVED")
    record_external_id(UUID, "sysdig", "staging", "42", tide_corpus_repo)
    fake = sysdig.fake
    fake.rules[42] = {"id": 42, "name": RULE_NAME, "version": 1}
    fake.policies[0]["ruleNames"] = [RULE_NAME]
    sysdig()
    assert fake.methods() == [
        ("GET", "/api/v2/policies"),
        ("PUT", "/api/v2/policies/7"),
        ("DELETE", "/api/secure/rules/42"),
    ]
    assert fake.policy_rules() == []
    assert _shard(tide_corpus_repo) is None


@pytest.mark.parametrize("status", ["DISABLED", "REMOVED"])
def test_retiring_without_a_binding_sends_nothing(
    sysdig: SysdigRun, tide_corpus_repo: Path, status: str
) -> None:
    _set_status(tide_corpus_repo, status)
    fake = sysdig()
    assert fake.calls == []
    assert _warned()
    assert not _failed()


def test_a_disabled_tuning_is_deleted(sysdig: SysdigRun, tide_corpus_repo: Path) -> None:
    path = tide_corpus_repo / "objects" / "rules" / "rule-0013-sysdig-falco.yaml"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "    condition: >\n      spawned_process and container\n"
        "      and proc.name in (corpus_shells)\n",
        "    append_to_rule: Terminal shell in container\n"
        "    condition: and not proc.name in (corpus_shells)\n",
    ).replace("    tags: [container, shell]\n", "")
    path.write_text(text.replace("    status: STAGING", "    status: DISABLED"), encoding="utf-8")
    clear_runtime_caches()
    record_external_id(UUID, "sysdig", "staging", "42", tide_corpus_repo)
    fake = sysdig.fake
    fake.rules[42] = {"id": 42, "name": "Terminal shell in container", "version": 1}
    sysdig()
    assert fake.methods() == [("GET", "/api/secure/rules/42"), ("DELETE", "/api/secure/rules/42")]
    assert _shard(tide_corpus_repo) is None


# --- api: failures --------------------------------------------------------------------


def test_a_missing_policy_fails_the_rule_but_keeps_its_id(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    fake = sysdig(_tenant(policies=["No such policy"]))
    assert ("POST", "/api/secure/rules") in fake.methods()
    assert _shard(tide_corpus_repo)["platforms"] == {"sysdig": {"staging": "42"}}
    assert _failed()


def test_a_refused_token_fails_the_tenant(sysdig: SysdigRun, tide_corpus_repo: Path) -> None:
    fake = sysdig.fake
    fake.status_override = 401
    sysdig()
    assert len(fake.calls) == 1
    assert _shard(tide_corpus_repo) is None
    assert _failed()


def test_a_ci_run_that_cannot_keep_the_id_creates_nothing(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    fake = sysdig(strategies=(StatusStrategy.PREVIEW,))
    assert fake.calls == []
    assert _failed()


def test_client_refuses_401_with_a_tenant_error() -> None:
    client = SysdigClient("https://x.example", "t", tenant="prod")
    client.session.request = lambda *a, **k: _response(403, {"message": "forbidden"})  # type: ignore[method-assign]
    with pytest.raises(SysdigTenantError, match="prod refused the API token: HTTP 403: forbidden"):
        client.list_policies()


# --- file delivery ------------------------------------------------------------------


def _file_tenant(rules_dir: str) -> Any:
    return _tenant(delivery="file", rules_dir=rules_dir, url="", api_token="")


def test_file_delivery_writes_one_rules_file_named_by_uuid(
    sysdig: SysdigRun, tide_corpus_repo: Path
) -> None:
    fake = sysdig(_file_tenant("deploy/falco"), strategies=(StatusStrategy.PREVIEW,))
    path = tide_corpus_repo / "deploy" / "falco" / f"{UUID}.yaml"
    data = path.read_bytes()
    assert b"\r\n" not in data
    text = data.decode("utf-8")
    assert text.startswith(f"# Generated by opentide from rule {UUID}.")
    assert "  enabled: true\n" in text
    assert "proc.name in (bash, sh, zsh)" in text
    assert fake.calls == []
    assert _shard(tide_corpus_repo) is None


def test_file_delivery_disables_then_deletes(sysdig: SysdigRun, tide_corpus_repo: Path) -> None:
    target = tide_corpus_repo / "rules.d"
    _set_status(tide_corpus_repo, "DISABLED")
    sysdig(_file_tenant(str(target)))
    path = target / f"{UUID}.yaml"
    assert "  enabled: false\n" in path.read_text(encoding="utf-8")
    _set_status(tide_corpus_repo, "REMOVED")
    path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    text = (tide_corpus_repo / "objects" / "rules" / "rule-0013-sysdig-falco.yaml").read_text(
        encoding="utf-8"
    )
    (tide_corpus_repo / "objects" / "rules" / "rule-0013-sysdig-falco.yaml").write_text(
        text.replace("status: DISABLED", "status: REMOVED"), encoding="utf-8"
    )
    clear_runtime_caches()
    sysdig(_file_tenant(str(target)))
    assert not path.exists()
    sysdig(_file_tenant(str(target)))  # already gone: not an error
    assert not _failed()
