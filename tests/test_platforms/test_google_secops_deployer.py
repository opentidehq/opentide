"""Google SecOps deploy: the Chronicle API v1 with deployment state (google-secops-1.0).

The HTTP boundary is a fake session that records every request and answers
like the Chronicle API. Everything above it is real: the client, the deployer,
the assembly, the deployment-state planner and shard writes. Request bodies are
compared with the specification goldens.
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
from tests.test_platforms.test_google_secops_compile import load_fixture_rule

from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.google_secops.client import (
    BACKOFF,
    GoogleSecopsApiError,
    GoogleSecopsClient,
    GoogleSecopsTenantError,
    load_credentials,
)
from opentide.platforms.google_secops.compile import assemble
from opentide.platforms.google_secops.deployer import GoogleSecopsDeploy, returned_rule_id
from opentide.platforms.transport import TenantSession
from opentide.states.deployment import (
    DeploymentStateError,
    normalise_external_id,
    record_external_id,
    shard_path,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "google_secops"
PROCESS = "rule-google-secops-process-1.0"
SPRAY = "rule-google-secops-spray-1.0"
UUID = {
    PROCESS: "00000000-0000-4000-8003-000000000061",
    SPRAY: "00000000-0000-4000-8003-000000000062",
}
INSTANCE = "projects/acme-secops/locations/eu/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6"
ENDPOINT = "https://eu-chronicle.googleapis.com"
BASE = f"/v1/{INSTANCE}"
RULE_ID = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1"
OTHER_ID = "ru_0b9f2c5e-1111-4222-8333-444455556666"
ALL = ["LIVE", "LIVE_CUSTOMIZABLE", "HOURLY_CUSTOMIZABLE", "DAILY"]
Tenant = ConfigurationModels.Systems.GoogleSecops.Tenant
TENANT = "secops-eu"


def _response(status: int, body: Any = None, headers: dict[str, str] | None = None) -> Any:
    response = requests.Response()
    response.status_code = status
    response._content = b"" if body is None else json.dumps(body).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    response.headers.update(headers or {})
    return response


def _error(status: int, code: str, message: str) -> Any:
    return _response(status, {"error": {"code": status, "status": code, "message": message}})


class FakeChronicle(TenantSession):
    """Rules and deployments, answered as the Chronicle API v1 answers them."""

    def __init__(self) -> None:
        super().__init__(verify=True)
        self.calls: list[dict[str, Any]] = []
        self.rules: dict[str, dict[str, Any]] = {}
        self.deployments: dict[str, dict[str, Any]] = {}
        self.ids = iter([RULE_ID, OTHER_ID])
        #: Answers queued ahead of the normal behaviour, each a callable of the call.
        self.script: list[Callable[[dict[str, Any]], Any]] = []
        self.allowed = list(ALL)

    def request(self, method: str, url: str, **kwargs: Any) -> Any:  # type: ignore[override]
        assert kwargs.get("timeout"), "every request has a timeout"
        assert kwargs["headers"]["Authorization"] == "Bearer token"
        assert url.startswith(ENDPOINT + BASE)
        call: dict[str, Any] = {"method": method, "path": url[len(ENDPOINT) :]}
        if kwargs.get("params"):
            call["query"] = dict(kwargs["params"])
        if kwargs.get("json") is not None:
            call["body"] = kwargs["json"]
        self.calls.append(call)
        if self.script:
            return self.script.pop(0)(call)
        return self._answer(call)

    def _answer(self, call: dict[str, Any]) -> Any:
        path, method = call["path"], call["method"]
        assert "force" not in (call.get("query") or {}), "never a forced delete"
        if path == f"{BASE}:verifyRuleText":
            return _response(200, {"success": True, "allowedRunFrequencies": self.allowed})
        if path == f"{BASE}/rules" and method == "POST":
            rule_id = next(self.ids)
            self.rules[rule_id] = {"text": call["body"]["text"], "etag": "e1"}
            self.deployments[rule_id] = {}
            return _response(200, {"name": f"{INSTANCE}/rules/{rule_id}"})
        rule_id = path[len(f"{BASE}/rules/") :].split("/")[0]
        if rule_id not in self.rules:
            return _error(404, "NOT_FOUND", "rule not found")
        if path.endswith("/deployment"):
            if method == "GET":
                return _response(200, self.deployments[rule_id])
            self.deployments[rule_id].update(call["body"])
            return _response(200, self.deployments[rule_id])
        if method == "GET":
            assert call["query"] == {"view": "FULL"}
            return _response(200, {**self.rules[rule_id], "allowedRunFrequencies": self.allowed})
        if method == "PATCH":
            if call["body"].get("etag") != self.rules[rule_id]["etag"]:
                return _error(409, "ABORTED", "etag mismatch")
            self.rules[rule_id] = {"text": call["body"]["text"], "etag": "e2"}
            return _response(200, self.rules[rule_id])
        if method == "DELETE":
            del self.rules[rule_id]
            return _response(200, {})
        raise AssertionError(f"unexpected {method} {path}")

    def paths(self) -> list[tuple[str, str]]:
        return [(call["method"], call["path"].rsplit("/", 1)[-1]) for call in self.calls]


class FakeCredentials:
    token: str | None = "token"
    valid = True

    def refresh(self, request: Any) -> None:
        raise AssertionError("valid credentials are not refreshed")


@pytest.fixture(autouse=True)
def _deployment_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


def _tenant(**setup: Any) -> Any:
    values = {field.name: None for field in dataclasses.fields(Tenant.Setup)} | {
        "ssl": True,
        "project": "acme-secops",
        "location": "eu",
        "instance": "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6",
        "deletion": "archive",
    }
    return Tenant(name=TENANT, description="", setup=Tenant.Setup(**(values | setup)))


def _rule(stem: str = PROCESS, status: str | None = None, **block: Any) -> DetectionRule:
    if status is not None:
        block["status"] = status
    return load_fixture_rule(stem, **block)


class Run:
    """Deploy one rule to one tenant against :attr:`fake`, with no real sleeps."""

    def __init__(self) -> None:
        self.fake = FakeChronicle()
        self.slept: list[float] = []

    def client(self) -> GoogleSecopsClient:
        return GoogleSecopsClient(
            endpoint=ENDPOINT,
            instance=INSTANCE,
            credentials=FakeCredentials(),
            tenant=TENANT,
            sleep=self.slept.append,
            session=self.fake,
        )

    def __call__(
        self,
        rule: DetectionRule | None = None,
        tenant: Any = None,
        strategies: Any = (StatusStrategy.RELEASE,),
    ) -> FakeChronicle:
        GoogleSecopsDeploy().deploy_tenant(
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


def _bound(repo: Path, stem: str = PROCESS) -> str | None:
    path = shard_path(UUID[stem], repo)
    if not path.exists():
        return None
    shard = json.loads(path.read_text(encoding="utf-8"))
    return shard.get("platforms", {}).get("google_secops", {}).get(TENANT)


def _bind(repo: Path, fake: FakeChronicle, stem: str = PROCESS, text: str | None = None) -> None:
    record_external_id(UUID[stem], "google_secops", TENANT, RULE_ID, repo)
    fake.rules[RULE_ID] = {"text": text if text is not None else "old text", "etag": "e1"}
    fake.deployments[RULE_ID] = {"enabled": True, "alerting": True, "runFrequency": "LIVE"}


def _failed() -> bool:
    return bool(os.environ.get("DEPLOYMENT_ERROR_RAISED"))


def _warned() -> bool:
    return bool(os.environ.get("DEPLOYMENT_WARNING_RAISED"))


def _golden(stem: str, step: str) -> Any:
    return json.loads((FIXTURES / f"{stem}.{step}.api.json").read_text(encoding="utf-8"))


# --- create --------------------------------------------------------------------------


@pytest.mark.parametrize(("stem", "status"), [(PROCESS, "STAGING"), (SPRAY, "PRODUCTION")])
def test_create_sends_the_goldens_and_records_the_id(
    run: Run, tide_corpus_repo: Path, stem: str, status: str
) -> None:
    fake = run(_rule(stem, status), strategies=(StatusStrategy.PREVIEW, StatusStrategy.RELEASE))
    assert fake.calls == [
        _golden(stem, "verify"),
        _golden(stem, "create"),
        _golden(stem, "deployment"),
    ]
    assert _bound(tide_corpus_repo, stem) == RULE_ID
    assert not _failed()


def test_a_data_access_scope_is_sent_on_create(run: Run) -> None:
    fake = run(tenant=_tenant(data_access_scope="soc"))
    assert fake.calls[1]["body"]["scope"] == f"{INSTANCE}/dataAccessScopes/soc"


def test_a_rule_that_does_not_verify_is_never_created(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.script.append(
        lambda _call: _response(
            200,
            {
                "compilationDiagnostics": [
                    {
                        "message": "field does not exist",
                        "severity": "ERROR",
                        "position": {"startLine": 15, "startColumn": 9},
                        "uri": "https://cloud.google.com/chronicle/docs/yara-l",
                    }
                ]
            },
        )
    )
    fake = run()
    assert [call["path"].rsplit(":", 1)[-1] for call in fake.calls] == ["verifyRuleText"]
    assert _bound(tide_corpus_repo) is None
    assert _failed()


def test_a_frequency_google_does_not_allow_fails_before_any_write(
    run: Run, tide_corpus_repo: Path
) -> None:
    run.fake.allowed = ["LIVE_CUSTOMIZABLE", "DAILY"]
    fake = run()  # the process rule asks for LIVE
    assert len(fake.calls) == 1
    assert _bound(tide_corpus_repo) is None
    assert _failed()


def test_the_first_allowed_frequency_is_the_default(run: Run) -> None:
    run.fake.allowed = ["HOURLY_CUSTOMIZABLE", "DAILY"]
    fake = run(_rule(run_frequency=None))
    assert fake.calls[-1]["body"]["runFrequency"] == "HOURLY_CUSTOMIZABLE"


def test_a_create_without_an_id_fails(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.script.extend(
        [
            lambda _call: _response(200, {"success": True, "allowedRunFrequencies": ALL}),
            lambda _call: _response(200, {"name": f"{INSTANCE}/rules/ru_1@v_1_2"}),
        ]
    )
    run()
    assert _bound(tide_corpus_repo) is None
    assert _failed()


def test_a_create_with_no_answer_is_unconfirmed_and_not_resent(
    run: Run, tide_corpus_repo: Path
) -> None:
    def timeout(_call: dict[str, Any]) -> Any:
        raise requests.ReadTimeout("read timed out")

    run.fake.script.extend(
        [lambda _call: _response(200, {"success": True, "allowedRunFrequencies": ALL}), timeout]
    )
    fake = run()
    assert len(fake.calls) == 2
    assert _bound(tide_corpus_repo) is None
    assert _failed()


def test_a_failed_deployment_update_keeps_the_binding(run: Run, tide_corpus_repo: Path) -> None:
    run.fake.script.extend(
        [
            lambda _call: _response(200, {"success": True, "allowedRunFrequencies": ALL}),
            lambda _call: _response(200, {"name": f"{INSTANCE}/rules/{RULE_ID}"}),
            lambda _call: _error(400, "INVALID_ARGUMENT", "bad run frequency"),
        ]
    )
    run()
    assert _bound(tide_corpus_repo) == RULE_ID
    assert _failed()


# --- update --------------------------------------------------------------------------


def test_an_unchanged_rule_sends_no_text_and_no_deployment(
    run: Run, tide_corpus_repo: Path
) -> None:
    rule = _rule(status="PRODUCTION")
    _bind(tide_corpus_repo, run.fake, text=assemble(rule).text)
    run.fake.deployments[RULE_ID] = {"enabled": True, "alerting": True, "runFrequency": "LIVE"}
    fake = run(rule)
    assert fake.paths() == [("GET", RULE_ID), ("GET", "deployment")]
    assert not _failed()


def test_a_changed_text_is_verified_then_patched_with_the_etag(
    run: Run, tide_corpus_repo: Path
) -> None:
    _bind(tide_corpus_repo, run.fake)
    rule = _rule(status="PRODUCTION")
    fake = run(rule)
    text = assemble(rule).text
    assert fake.calls[1] == _golden(PROCESS, "verify")
    assert fake.calls[2] == {
        "method": "PATCH",
        "path": f"{BASE}/rules/{RULE_ID}",
        "query": {"updateMask": "text"},
        "body": {"text": text, "etag": "e1"},
    }
    assert fake.rules[RULE_ID]["text"] == text
    assert not _failed()


def test_the_scope_is_sent_with_an_update(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, run.fake)
    fake = run(tenant=_tenant(data_access_scope="soc"))
    patch = next(call for call in fake.calls if call["method"] == "PATCH")
    assert patch["query"] == {"updateMask": "text,scope"}
    assert patch["body"]["scope"] == f"{INSTANCE}/dataAccessScopes/soc"


def test_a_preview_rule_runs_without_alerting(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, run.fake)
    fake = run(strategies=(StatusStrategy.PREVIEW,))
    assert fake.calls[-1] == _golden(PROCESS, "deployment")
    assert fake.deployments[RULE_ID]["alerting"] is False


def test_an_archived_rule_is_unarchived_first(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, run.fake)
    run.fake.deployments[RULE_ID] = {"archived": True}
    fake = run(_rule(status="PRODUCTION"))
    patches = [call for call in fake.calls if call["path"].endswith("/deployment")]
    assert [call.get("query") for call in patches if call["method"] == "PATCH"] == [
        {"updateMask": "archived"},
        {"updateMask": "enabled,alerting,runFrequency"},
    ]
    assert patches[1]["body"] == {"archived": False}


def test_a_verify_error_on_update_fails_the_rule_only(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, run.fake)
    run.fake.script.extend(
        [
            lambda call: run.fake._answer(call),
            lambda _call: _error(400, "INVALID_ARGUMENT", "rule text too long"),
        ]
    )
    fake = run()
    assert [call["method"] for call in fake.calls] == ["GET", "POST"]
    assert _bound(tide_corpus_repo) == RULE_ID
    assert _failed()


def test_a_stale_etag_is_a_conflict(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, run.fake)
    # The rule changes between the read and the update.
    run.fake.script.append(
        lambda _call: _response(200, {"text": "old", "etag": "e0", "allowedRunFrequencies": ALL})
    )
    fake = run()
    assert fake.paths()[-1] == ("PATCH", RULE_ID)
    assert fake.rules[RULE_ID]["text"] == "old text"
    assert _bound(tide_corpus_repo) == RULE_ID
    assert _failed()


def test_a_rule_gone_is_created_again(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID[PROCESS], "google_secops", TENANT, OTHER_ID, tide_corpus_repo)
    fake = run()
    assert fake.paths()[:2] == [
        ("GET", OTHER_ID),
        ("POST", "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6:verifyRuleText"),
    ]
    assert _bound(tide_corpus_repo) == RULE_ID
    assert _warned() and not _failed()


# --- DISABLEMENT and DELETION --------------------------------------------------------


def test_disablement_keeps_the_text_current_and_disables(run: Run, tide_corpus_repo: Path) -> None:
    rule = _rule(status="DISABLED")
    _bind(tide_corpus_repo, run.fake, text=assemble(rule).text)
    fake = run(rule)
    assert fake.calls[-1] == _golden(PROCESS, "disable")
    assert _bound(tide_corpus_repo) == RULE_ID
    assert not _failed()


def test_disabling_a_rule_gone_forgets_it(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID[PROCESS], "google_secops", TENANT, OTHER_ID, tide_corpus_repo)
    fake = run(_rule(status="DISABLED"))
    assert fake.paths() == [("GET", OTHER_ID)]
    assert _bound(tide_corpus_repo) is None
    assert _warned() and not _failed()


def test_deletion_archives_by_default(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, run.fake)
    fake = run(_rule(status="REMOVED"))
    patches = [call for call in fake.calls if call["method"] == "PATCH"]
    assert patches == _golden(PROCESS, "archive")
    assert _bound(tide_corpus_repo) == RULE_ID
    assert RULE_ID in fake.rules
    assert not _failed()


def test_an_archived_rule_is_not_archived_again(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, run.fake)
    run.fake.deployments[RULE_ID] = {"archived": True}
    fake = run(_rule(status="REMOVED"))
    assert fake.paths() == [("GET", "deployment")]


def test_deletion_deletes_without_force_when_the_tenant_asks(
    run: Run, tide_corpus_repo: Path
) -> None:
    _bind(tide_corpus_repo, run.fake)
    fake = run(_rule(status="REMOVED"), tenant=_tenant(deletion="delete"))
    assert fake.calls == [{"method": "DELETE", "path": f"{BASE}/rules/{RULE_ID}"}]
    assert _bound(tide_corpus_repo) is None
    assert not _failed()


def test_a_refused_delete_archives_instead(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo, run.fake)
    run.fake.script.append(lambda _call: _error(400, "FAILED_PRECONDITION", "rule has detections"))
    fake = run(_rule(status="REMOVED"), tenant=_tenant(deletion="delete"))
    assert [call for call in fake.calls if call["method"] == "PATCH"] == _golden(PROCESS, "archive")
    assert _bound(tide_corpus_repo) == RULE_ID
    assert _warned() and not _failed()


def test_deleting_a_rule_already_gone_succeeds(run: Run, tide_corpus_repo: Path) -> None:
    record_external_id(UUID[PROCESS], "google_secops", TENANT, OTHER_ID, tide_corpus_repo)
    run(_rule(status="REMOVED"), tenant=_tenant(deletion="delete"))
    assert _bound(tide_corpus_repo) is None
    assert not _failed()


def test_disable_or_delete_without_a_binding_makes_no_call(run: Run) -> None:
    for status in ("DISABLED", "REMOVED"):
        fake = run(_rule(status=status))
        assert fake.calls == []
    assert _warned() and not _failed()


# --- the tenant ----------------------------------------------------------------------


def test_refused_credentials_stop_the_tenant(run: Run) -> None:
    run.fake.script.append(lambda _call: _error(403, "PERMISSION_DENIED", "no permission"))
    fake = Run.__call__(run, _rule())
    assert len(fake.calls) == 1
    assert _failed()


def test_rate_limits_are_waited_out_with_retry_after_or_backoff(run: Run) -> None:
    run.fake.script.extend(
        [
            lambda _call: _error(429, "RESOURCE_EXHAUSTED", "quota"),
            lambda _call: _response(503, None, {"Retry-After": "7"}),
        ]
    )
    client = run.client()
    assert client.verify("rule x {}")["success"] is True
    assert run.slept == [BACKOFF[0], 7.0]
    assert len(run.fake.calls) == 3


def test_the_rate_limit_gives_up_after_three_waits(run: Run) -> None:
    run.fake.script.extend([lambda _call: _error(429, "RESOURCE_EXHAUSTED", "quota")] * 4)
    with pytest.raises(GoogleSecopsApiError) as caught:
        run.client().verify("rule x {}")
    assert caught.value.status == "RESOURCE_EXHAUSTED"
    assert run.slept == list(BACKOFF)


def test_an_answer_that_is_not_json_names_its_status(run: Run) -> None:
    def html(_call: dict[str, Any]) -> Any:
        response = requests.Response()
        response.status_code = 502
        response._content = b"<html><title>Bad gateway</title></html>"
        response.headers["Content-Type"] = "text/html"
        return response

    run.fake.script.append(html)
    with pytest.raises(GoogleSecopsApiError, match="Bad gateway"):
        run.client().verify("rule x {}")


def test_expired_credentials_are_refreshed_on_the_tenant_session() -> None:
    class Expiring(FakeCredentials):
        valid = False
        token = None

        def refresh(self, request: Any) -> None:
            assert request.session is fake
            self.token, self.valid = "token", True

    fake = FakeChronicle()
    client = GoogleSecopsClient(
        endpoint=ENDPOINT, instance=INSTANCE, credentials=Expiring(), tenant=TENANT, session=fake
    )
    client.verify("rule x {}")
    assert len(fake.calls) == 1


def test_a_refused_refresh_is_unauthorized() -> None:
    from google.auth.exceptions import RefreshError

    class Refused(FakeCredentials):
        valid = False

        def refresh(self, request: Any) -> None:
            raise RefreshError("invalid_grant")

    client = GoogleSecopsClient(
        endpoint=ENDPOINT,
        instance=INSTANCE,
        credentials=Refused(),
        tenant=TENANT,
        session=FakeChronicle(),
    )
    with pytest.raises(GoogleSecopsTenantError) as caught:
        client.verify("rule x {}")
    assert caught.value.code == "google_secops_tenant_unauthorized"


# --- credentials ---------------------------------------------------------------------


def test_an_unset_credentials_variable_is_refused() -> None:
    with pytest.raises(GoogleSecopsTenantError, match="GOOGLE_SECOPS_CREDENTIALS is not set"):
        load_credentials("$GOOGLE_SECOPS_CREDENTIALS")


def test_credentials_that_are_neither_json_nor_a_file_are_refused(tmp_path: Path) -> None:
    with pytest.raises(GoogleSecopsTenantError, match="names no file"):
        load_credentials(str(tmp_path / "missing.json"))
    with pytest.raises(GoogleSecopsTenantError, match="cannot load Google credentials"):
        load_credentials('{"type": "nonsense"}')


def test_a_service_account_key_loads_from_json_or_a_path(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    info = {
        "type": "service_account",
        "project_id": "acme-secops",
        "private_key_id": "1",
        "private_key": pem,
        "client_email": "opentide@acme-secops.iam.gserviceaccount.com",
        "client_id": "1",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    from_json = load_credentials(json.dumps(info))
    path = tmp_path / "key.json"
    path.write_text(json.dumps(info), encoding="utf-8")
    from_path = load_credentials(str(path))
    for credentials in (from_json, from_path):
        assert getattr(credentials, "scopes", None) == [
            "https://www.googleapis.com/auth/cloud-platform"
        ]


# --- ids -----------------------------------------------------------------------------


def test_the_rule_id_is_read_from_the_resource_name() -> None:
    assert returned_rule_id(f"{INSTANCE}/rules/{RULE_ID}") == RULE_ID
    assert returned_rule_id(RULE_ID) == RULE_ID
    assert returned_rule_id(f"{INSTANCE}/rules/{RULE_ID}@v_1704475682_607535000") is None
    assert returned_rule_id(None) is None


@pytest.mark.parametrize(
    "value",
    [RULE_ID[3:], RULE_ID.upper(), f"{RULE_ID}@v_1_2", f"{INSTANCE}/rules/{RULE_ID}", 12],
)
def test_deployment_state_takes_only_a_rule_id(value: object) -> None:
    with pytest.raises(DeploymentStateError) as caught:
        normalise_external_id("google_secops", value)
    assert caught.value.code == "external_id_shape"
    assert normalise_external_id("google_secops", RULE_ID) == RULE_ID
