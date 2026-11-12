"""Graylog deploy: event definitions with deployment state (graylog-1.0).

The HTTP boundary is a fake Graylog behind the client's ``requests`` session: it
records every call and answers as Graylog 6.3.5 and 7.2.2 did when the request
goldens were checked (404 on a PUT of a missing id, 204 on a DELETE of one, the
``/api/search/validate`` verdicts). Everything above it is real: the client, the
deployer, the compiler, the deployment-state planner and shard writes.
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
from opentide.platforms.graylog import deployer as deployer_module
from opentide.platforms.graylog.client import (
    GraylogApiError,
    GraylogClient,
    GraylogTenantError,
    explanation_text,
    read_verdict,
    returned_id,
)
from opentide.platforms.graylog.deployer import GraylogDeploy
from opentide.states.deployment import (
    DeploymentStateError,
    normalise_external_id,
    record_external_id,
    shard_path,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "graylog"
UUID = "00000000-0000-4000-8003-000000000060"
OTHER_UUID = "00000000-0000-4000-8003-000000000061"
RELEASE = (StatusStrategy.RELEASE,)
Tenant = ConfigurationModels.Systems.Graylog.Tenant
URL = "https://graylog.example.com"
TENANT = "graylog-prod"
SAMPLE_ID = "65f1c0de2a3b4c5d6e7f8091"
NEXT_ID = "65f1c0de2a3b4c5d6e7f8092"
DEFINITIONS = "/api/events/definitions"


def _response(status: int, body: Any = None) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = b"" if body is None else json.dumps(body).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


class FakeGraylog:
    """Event definitions and the search validator, answered as Graylog answers them."""

    def __init__(self, version: str = "7.2.2+94adc86") -> None:
        self.version = version
        self.calls: list[dict[str, Any]] = []
        self.definitions: dict[str, dict[str, Any]] = {}
        self.ids = iter([SAMPLE_ID.upper(), NEXT_ID, "65f1c0de2a3b4c5d6e7f8093"])
        self.verdict: dict[str, Any] = {"status": "OK", "explanations": []}
        #: Answers queued per ``(method, path prefix)``, each a callable of the body.
        self.script: list[tuple[str, str, Callable[[Any], requests.Response]]] = []
        self.session: requests.Session | None = None

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        assert url.startswith(URL + "/api/")
        assert kwargs.get("timeout"), "every request has a timeout"
        assert kwargs.get("allow_redirects") is False
        path = url[len(URL) :]
        body = kwargs.get("json")
        assert "/execute" not in path and "paginated" not in path
        self.calls.append({"method": method, "path": path, "body": body})
        for index, (want_method, prefix, answer) in enumerate(self.script):
            if want_method == method and path.startswith(prefix):
                del self.script[index]
                return answer(body)
        if (method, path) == ("GET", "/api/system"):
            return _response(200, {"version": self.version, "facility": "graylog-server"})
        if (method, path) == ("POST", "/api/search/validate"):
            return _response(200, self.verdict)
        if method == "POST" and path == f"{DEFINITIONS}?schedule=true":
            definition = body.get("entity", body)
            assert "id" not in definition, "never an id on create"
            definition_id = next(self.ids)
            self.definitions[definition_id.lower()] = definition
            return _response(200, {**definition, "id": definition_id, "state": "DISABLED"})
        if method == "PUT" and path.startswith(DEFINITIONS + "/"):
            definition_id = path[len(DEFINITIONS) + 1 :].split("?")[0]
            assert path.endswith(("?schedule=true", "?schedule=false"))
            assert body["id"] == definition_id
            if definition_id not in self.definitions:
                return _response(
                    404,
                    {
                        "type": "ApiError",
                        "message": f"Event definition <{definition_id}> doesn't exist",
                    },
                )
            self.definitions[definition_id] = body
            return _response(200, body)
        if method == "DELETE" and path.startswith(DEFINITIONS + "/"):
            definition_id = path[len(DEFINITIONS) + 1 :]
            if self.definitions.pop(definition_id, None) is None:
                return _response(204)
            return _response(200, {"id": definition_id})
        raise AssertionError(f"unexpected {method} {path}")

    def methods(self) -> list[str]:
        return [f"{call['method']} {call['path'].split('?')[0]}" for call in self.calls]


@pytest.fixture(autouse=True)
def _deployment_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


@pytest.fixture
def codes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every error and warning code the deployer reports, in order."""
    seen: list[str] = []
    error, warning = deployer_module._deployment_error, deployer_module._deployment_warning
    tenant_failed = GraylogDeploy._tenant_failed

    def record_error(code: str, **kwargs: Any) -> None:
        seen.append(code)
        error(code, **kwargs)

    def record_warning(code: str, **kwargs: Any) -> None:
        seen.append(code)
        warning(code, **kwargs)

    def record_tenant(tenant: Any, code: str | None, message: str) -> None:
        seen.append(code or "tenant_failed")
        tenant_failed(tenant, code, message)

    def record_state(error: DeploymentStateError, **kwargs: Any) -> None:
        seen.append(error.code)
        os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"

    monkeypatch.setattr(deployer_module, "_deployment_error", record_error)
    monkeypatch.setattr(deployer_module, "_deployment_warning", record_warning)
    monkeypatch.setattr(GraylogDeploy, "_tenant_failed", staticmethod(record_tenant))
    monkeypatch.setattr(deployer_module, "report_failure", record_state)
    return seen


def _tenant(**setup: Any) -> Any:
    values = {field.name: None for field in dataclasses.fields(Tenant.Setup)} | {
        "ssl": True,
        "url": URL,
        "token": "token-value",
        "allow_leading_wildcard": False,
        "streams": ["sysmon"],
        "tags": ["managed-by-opentide"],
        "stream_ids": {
            "sysmon": "65f0c0ffee0123456789abcd",
            "windows-security": "65f0c0ffee0123456789abce",
        },
        "notification_ids": {"soc-slack": "65f0c0ffee0123456789abcf"},
    }
    return Tenant(name=TENANT, description="", setup=Tenant.Setup(**(values | setup)))


def _rule(
    status: str = "STAGING", name: str = "rule-graylog-aggregation-1.0.yaml"
) -> DetectionRule:
    document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    document["configurations"]["graylog"]["status"] = status
    return load_rule_from_dict(document)


class Run:
    """Deploy rules to one tenant against :attr:`fake`."""

    def __init__(self) -> None:
        self.fake = FakeGraylog()

    def client(self) -> GraylogClient:
        built = GraylogClient(URL, "token-value", tenant=TENANT)
        self.fake.session = built.session
        built.session.request = self.fake.request  # type: ignore[method-assign]
        return built

    def __call__(
        self, *rules: DetectionRule, tenant: Any = None, strategies: Any = RELEASE
    ) -> FakeGraylog:
        GraylogDeploy().deploy_tenant(
            list(rules) or [_rule()], tenant or _tenant(), strategies, client=self.client()
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


def _shard(repo: Path, uuid: str = UUID) -> dict[str, Any] | None:
    path = shard_path(uuid, repo)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _bound(repo: Path, uuid: str = UUID) -> str | None:
    shard = _shard(repo, uuid)
    return (shard or {}).get("platforms", {}).get("graylog", {}).get(TENANT)


def _bind(repo: Path, definition_id: str = SAMPLE_ID, uuid: str = UUID) -> None:
    record_external_id(uuid, "graylog", TENANT, definition_id, repo)


def _failed() -> bool:
    return bool(os.environ.get("DEPLOYMENT_ERROR_RAISED"))


def _warned() -> bool:
    return bool(os.environ.get("DEPLOYMENT_WARNING_RAISED"))


def _golden(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _request(call: dict[str, Any]) -> dict[str, Any]:
    return {"method": call["method"], "path": call["path"], "body": call["body"]}


# --- create, update, disable, delete ---------------------------------------------------


def test_create_reads_the_version_checks_the_query_and_records_the_id(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    fake = run()
    assert fake.methods() == ["GET /api/system", "POST /api/search/validate", f"POST {DEFINITIONS}"]
    assert _request(fake.calls[2]) == _golden("rule-graylog-aggregation-1.0.7.2.create.api.json")
    assert fake.calls[1]["body"] == {
        "query": fake.calls[2]["body"]["entity"]["config"]["query"],
        "streams": ["65f0c0ffee0123456789abcd"],
        "stream_categories": [],
        "timerange": {"type": "relative", "range": 900},
    }
    assert _bound(tide_corpus_repo) == SAMPLE_ID, "the returned id is lower-cased"
    assert not _failed() and codes == []


@pytest.mark.parametrize(
    ("version", "golden"),
    [
        ("6.3.5+eaa4b5d", "rule-graylog-aggregation-1.0.6.3.create.api.json"),
        ("7.0.16+abc", "rule-graylog-aggregation-1.0.7.0.create.api.json"),
    ],
)
def test_create_bodies_follow_the_server_version(
    run: Run, version: str, golden: str, codes: list[str]
) -> None:
    run.fake.version = version
    fake = run()
    assert _request(fake.calls[2]) == _golden(golden)
    assert codes.count("graylog_field_unsupported_version") == 2


def test_create_body_for_7_1_and_its_priority(run: Run, codes: list[str]) -> None:
    run.fake.version = "7.1.12"
    fake = run(_rule(name="rule-graylog-filter-1.1.yaml"))
    assert _request(fake.calls[2]) == _golden("rule-graylog-filter-1.1.7.1.create.api.json")
    assert codes == []


def test_informational_is_collapsed_before_7_1(run: Run, codes: list[str]) -> None:
    run.fake.version = "6.3.12"
    fake = run(_rule(name="rule-graylog-filter-1.1.yaml"))
    assert _request(fake.calls[2]) == _golden("rule-graylog-filter-1.1.6.3.create.api.json")
    assert codes == ["graylog_priority_collapsed"]


def test_update_sends_the_whole_definition_and_keeps_the_binding(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    _bind(tide_corpus_repo)
    run.fake.definitions[SAMPLE_ID] = {}
    fake = run()
    assert fake.methods()[-1] == f"PUT {DEFINITIONS}/{SAMPLE_ID}"
    assert _request(fake.calls[-1]) == _golden("rule-graylog-aggregation-1.0.7.2.update.api.json")
    assert _bound(tide_corpus_repo) == SAMPLE_ID
    assert not _failed() and codes == []


def test_disablement_is_a_put_with_schedule_false(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    _bind(tide_corpus_repo)
    run.fake.definitions[SAMPLE_ID] = {}
    fake = run(_rule("DISABLED"))
    # No query check: an unscheduled definition never runs its query (graylog-1.1).
    assert fake.methods() == ["GET /api/system", f"PUT {DEFINITIONS}/{SAMPLE_ID}"]
    assert _request(fake.calls[-1]) == _golden("rule-graylog-aggregation-1.0.7.2.disable.api.json")
    assert _bound(tide_corpus_repo) == SAMPLE_ID
    assert codes == []


def test_a_rule_graylog_now_refuses_can_still_be_disabled(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    _bind(tide_corpus_repo)
    run.fake.definitions[SAMPLE_ID] = {}
    run.fake.verdict = {"status": "ERROR", "explanations": []}
    fake = run(_rule("DISABLED"))
    assert fake.methods()[-1] == f"PUT {DEFINITIONS}/{SAMPLE_ID}"
    assert "schedule=false" in fake.calls[-1]["path"]
    assert codes == [] and not _failed()


def test_deletion_deletes_and_forgets(run: Run, tide_corpus_repo: Path, codes: list[str]) -> None:
    _bind(tide_corpus_repo)
    run.fake.definitions[SAMPLE_ID] = {}
    fake = run(_rule("REMOVED"))
    assert fake.methods() == ["GET /api/system", f"DELETE {DEFINITIONS}/{SAMPLE_ID}"]
    assert fake.calls[-1]["body"] is None
    assert _bound(tide_corpus_repo) is None
    assert not _failed() and codes == []


def test_deleting_a_definition_already_gone_succeeds(run: Run, tide_corpus_repo: Path) -> None:
    """Graylog answers 204 for an id it does not have: any 2xx removes the binding."""
    _bind(tide_corpus_repo)
    run(_rule("REMOVED"))
    assert _bound(tide_corpus_repo) is None
    assert not _failed()


def test_disable_or_delete_without_a_binding_makes_no_call(run: Run) -> None:
    for status in ("DISABLED", "REMOVED"):
        fake = run(_rule(status))
        assert fake.calls == []
    assert _warned() and not _failed()


def test_the_version_is_read_once_per_tenant_per_run(run: Run, tide_corpus_repo: Path) -> None:
    fake = run(_rule(), _rule(name="rule-graylog-filter-1.1.yaml"))
    assert fake.methods().count("GET /api/system") == 1
    assert fake.methods().count(f"POST {DEFINITIONS}") == 2
    assert _bound(tide_corpus_repo, OTHER_UUID) == NEXT_ID


def test_every_request_carries_the_headers_and_the_token(run: Run) -> None:
    run()
    session = run.fake.session
    assert session is not None
    assert session.headers["Accept"] == "application/json"
    assert session.headers["X-Requested-By"] == "opentide"
    assert session.auth == ("token-value", "token")


# --- the server version --------------------------------------------------------------


@pytest.mark.parametrize("version", ["6.2.4+1a2b3c4", "5.0.0", None, "unknown"])
def test_an_unsupported_version_stops_the_tenant_before_any_write(
    run: Run, version: str | None, codes: list[str], tide_corpus_repo: Path
) -> None:
    run.fake.version = version  # type: ignore[assignment]
    fake = run(_rule(), _rule(name="rule-graylog-filter-1.1.yaml"))
    assert fake.methods() == ["GET /api/system"]
    assert codes == ["graylog_version_unsupported"]
    assert _failed() and _bound(tide_corpus_repo) is None


def test_a_vulnerable_version_warns_once_and_deploys(run: Run, codes: list[str]) -> None:
    run.fake.version = "7.0.15"
    fake = run(_rule(), _rule(name="rule-graylog-filter-1.1.yaml"))
    assert codes.count("graylog_version_vulnerable") == 1
    assert fake.methods().count(f"POST {DEFINITIONS}") == 2
    assert not _failed()


def test_a_fixed_version_does_not_warn(run: Run, codes: list[str]) -> None:
    run.fake.version = "7.1.12"
    run()
    assert "graylog_version_vulnerable" not in codes


# --- the pre-save query check ---------------------------------------------------------


def test_a_query_graylog_reports_as_error_is_never_saved(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    run.fake.verdict = {
        "status": "ERROR",
        "explanations": [
            {
                "error_type": "QUERY_PARSING_ERROR",
                "begin_line": 1,
                "begin_column": 0,
                "error_title": "Query parsing error",
                "error_message": "Cannot parse query, cause: incomplete query",
            }
        ],
    }
    fake = run()
    assert fake.methods() == ["GET /api/system", "POST /api/search/validate"]
    assert codes == ["graylog_query_invalid"]
    assert _failed() and _bound(tide_corpus_repo) is None


def test_an_update_whose_query_fails_saves_nothing(run: Run, tide_corpus_repo: Path) -> None:
    _bind(tide_corpus_repo)
    run.fake.definitions[SAMPLE_ID] = {}
    run.fake.verdict = {"status": "ERROR", "explanations": []}
    fake = run()
    assert not any(call["method"] == "PUT" for call in fake.calls)
    assert _failed() and _bound(tide_corpus_repo) == SAMPLE_ID


def test_query_warnings_are_reported_and_the_definition_saved(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    run.fake.verdict = {
        "status": "WARNING",
        "explanations": [
            {"error_type": "UNKNOWN_FIELD", "error_title": "Unknown field", "error_message": "x"},
            {"error_type": "INVALID_VALUE_TYPE", "error_message": "Type of EventID is long"},
            {"error_type": "INVALID_OPERATOR", "error_message": "and"},
            {"error_type": "SOMETHING_NEW", "error_message": "?"},
        ],
    }
    run()
    assert codes == [
        "graylog_unknown_field",
        "graylog_value_type",
        "graylog_query_warning",
        "graylog_query_warning",
    ]
    assert _bound(tide_corpus_repo) == SAMPLE_ID and not _failed()


def test_read_verdict() -> None:
    errors, warnings = read_verdict(
        {
            "status": "ERROR",
            "explanations": [
                {
                    "error_type": "QUERY_PARSING_ERROR",
                    "error_title": "Query parsing error",
                    "error_message": "'*' or '?' not allowed as first character",
                },
                {
                    "error_type": "UNKNOWN_FIELD",
                    "error_message": "unknown field: x",
                    "begin_line": 1,
                    "begin_column": 4,
                },
            ],
        }
    )
    assert errors == ["Query parsing error: '*' or '?' not allowed as first character"]
    assert warnings == [
        ("graylog_unknown_field", "UNKNOWN_FIELD: unknown field: x (line 1, column 4)")
    ]
    assert read_verdict({"status": "OK"}) == ([], [])
    assert read_verdict({"status": "ERROR"}) == (["Graylog reports the query as ERROR"], [])
    assert explanation_text("plain") == "plain"


# --- the definition is gone ----------------------------------------------------------


def test_an_update_of_a_definition_gone_creates_it_again(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    _bind(tide_corpus_repo, NEXT_ID)
    fake = run()
    assert fake.methods()[-2:] == [f"PUT {DEFINITIONS}/{NEXT_ID}", f"POST {DEFINITIONS}"]
    assert _bound(tide_corpus_repo) == SAMPLE_ID
    assert codes == ["graylog_definition_recreated"]
    assert _warned() and not _failed()


def test_disabling_a_definition_gone_forgets_it(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    _bind(tide_corpus_repo)
    fake = run(_rule("DISABLED"))
    assert f"POST {DEFINITIONS}" not in fake.methods()
    assert _bound(tide_corpus_repo) is None
    assert codes == ["graylog_definition_missing"]
    assert _warned() and not _failed()


def test_a_recreate_is_refused_when_state_cannot_be_kept(
    run: Run, tide_corpus_repo: Path, codes: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _bind(tide_corpus_repo, NEXT_ID)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    fake = run(strategies=(StatusStrategy.PREVIEW, StatusStrategy.RELEASE))
    assert f"POST {DEFINITIONS}" not in fake.methods()
    assert codes == ["graylog_definition_recreated", "deployment_state_unpersisted"]
    assert _failed()


# --- the failure table ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "code"),
    [
        ("Immutable entity cannot be modified", "graylog_definition_immutable"),
        ("something else went wrong", "graylog_request_failed"),
    ],
)
def test_a_refused_update_fails_the_rule_and_keeps_the_binding(
    run: Run, tide_corpus_repo: Path, codes: list[str], message: str, code: str
) -> None:
    _bind(tide_corpus_repo)
    run.fake.definitions[SAMPLE_ID] = {}
    status = 400 if "Immutable" in message else 500
    run.fake.script.append(
        (
            "PUT",
            DEFINITIONS,
            lambda body: _response(status, {"type": "ApiError", "message": message}),
        )
    )
    run()
    assert codes == [code]
    assert _failed() and _bound(tide_corpus_repo) == SAMPLE_ID


@pytest.mark.parametrize(
    ("status", "message", "code"),
    [
        (400, "Non-deletable entity cannot be deleted", "graylog_definition_immutable"),
        (
            400,
            "Event definition is still in use by correlation <Brute force then login>",
            "graylog_definition_in_use",
        ),
        (403, "Not authorized", "graylog_forbidden"),
    ],
)
def test_a_refused_delete_keeps_the_binding(
    run: Run, tide_corpus_repo: Path, codes: list[str], status: int, message: str, code: str
) -> None:
    _bind(tide_corpus_repo)
    run.fake.script.append(
        (
            "DELETE",
            DEFINITIONS,
            lambda body: _response(status, {"type": "ApiError", "message": message}),
        )
    )
    run(_rule("REMOVED"))
    assert codes == [code]
    assert _failed() and _bound(tide_corpus_repo) == SAMPLE_ID


def test_a_refused_body_names_its_fields(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    run.fake.script.append(
        (
            "POST",
            DEFINITIONS,
            lambda body: _response(
                400,
                {"errors": {"title": ["Event Definition title cannot be empty."]}, "failed": True},
            ),
        )
    )
    run()
    assert codes == ["graylog_definition_invalid"]
    assert _failed() and _bound(tide_corpus_repo) is None


def test_a_forbidden_create_fails_the_rule_and_the_next_one_is_sent(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    run.fake.script.append(
        ("POST", DEFINITIONS, lambda body: _response(403, {"message": "Not authorized"}))
    )
    fake = run(_rule(), _rule(name="rule-graylog-filter-1.1.yaml"))
    assert codes == ["graylog_forbidden"]
    assert fake.methods().count(f"POST {DEFINITIONS}") == 2
    assert _bound(tide_corpus_repo) is None
    assert _bound(tide_corpus_repo, OTHER_UUID) is not None


@pytest.mark.parametrize("step", ["/api/system", "/api/search/validate", DEFINITIONS])
def test_401_stops_the_tenant(run: Run, codes: list[str], step: str) -> None:
    method = "GET" if step == "/api/system" else "POST"
    run.fake.script.append((method, step, lambda body: _response(401)))
    fake = run(_rule(), _rule(name="rule-graylog-filter-1.1.yaml"))
    assert codes == ["graylog_tenant_unauthorized"]
    assert fake.calls[-1]["path"].startswith(step), "nothing is sent after the 401"
    assert _failed()


def test_an_unknown_alias_fails_before_any_call_for_the_rule(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    fake = run(tenant=_tenant(notification_ids={}))
    assert fake.methods() == ["GET /api/system"]
    assert codes == ["graylog_alias_unknown"]
    assert _failed() and _bound(tide_corpus_repo) is None


@pytest.mark.parametrize(
    "error", [requests.ConnectionError("connection reset"), requests.ReadTimeout("read timed out")]
)
def test_a_create_with_no_answer_is_never_retried(
    run: Run, tide_corpus_repo: Path, codes: list[str], error: Exception
) -> None:
    def lost(body: Any) -> requests.Response:
        raise error

    run.fake.script.append(("POST", DEFINITIONS, lost))
    other = _rule(name="rule-graylog-filter-1.1.yaml")
    fake = run(_rule(), other)
    creates = [call for call in fake.calls if call["path"].startswith(DEFINITIONS)]
    assert len(creates) == 2, "the first create is not retried; the next rule is still sent"
    assert codes[0] == "graylog_create_unconfirmed"
    assert _bound(tide_corpus_repo) is None
    assert _failed()


def test_the_unconfirmed_create_names_the_title_and_the_uuid_tag(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(
        deployer_module, "_deployment_error", lambda code, **kwargs: seen.append(kwargs)
    )

    def lost(body: Any) -> requests.Response:
        raise requests.ConnectionError("reset")

    run.fake.script.append(("POST", DEFINITIONS, lost))
    run()
    error = seen[0]["error"]
    assert "'Office application spawns obfuscated PowerShell'" in error
    assert f"'opentide.{UUID}'" in error


def test_a_create_answering_no_id_fails_the_rule(
    run: Run, tide_corpus_repo: Path, codes: list[str]
) -> None:
    run.fake.script.append(("POST", DEFINITIONS, lambda body: _response(200, {"title": "x"})))
    run()
    assert codes == ["graylog_create_unconfirmed"]
    assert _bound(tide_corpus_repo) is None


@pytest.mark.parametrize(
    ("status", "content"),
    [(201, b""), (200, b"<html>proxy page</html>")],
)
def test_a_create_answering_2xx_without_json_is_unconfirmed(
    run: Run, tide_corpus_repo: Path, codes: list[str], status: int, content: bytes
) -> None:
    def answer(body: Any) -> requests.Response:
        response = _response(status)
        response._content = content
        response.headers["Content-Type"] = "text/html"
        return response

    run.fake.script.append(("POST", DEFINITIONS, answer))
    run()
    # The definition may exist: unconfirmed (find it by title or tag), not a failed request.
    assert codes == ["graylog_create_unconfirmed"]
    assert _bound(tide_corpus_repo) is None
    assert _failed()


def test_an_unreachable_tenant_stops(run: Run, codes: list[str]) -> None:
    def down(body: Any) -> requests.Response:
        raise requests.ConnectionError("refused")

    run.fake.script.append(("GET", "/api/system", down))
    fake = run()
    assert codes == ["graylog_tenant_unreachable"]
    assert len(fake.calls) == 1


def test_a_forbidden_version_read_stops_the_tenant(run: Run, codes: list[str]) -> None:
    run.fake.script.append(("GET", "/api/system", lambda body: _response(403, {"message": "no"})))
    fake = run()
    assert codes == ["graylog_forbidden"]
    assert len(fake.calls) == 1


# --- the client ----------------------------------------------------------------------


def test_an_unset_token_variable_is_refused() -> None:
    with pytest.raises(ValueError):
        GraylogClient(URL, "$GRAYLOG_TOKEN", tenant=TENANT)


def test_an_unset_token_fails_the_tenant_without_a_call(
    tide_corpus_repo: Path, codes: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    del tide_corpus_repo
    monkeypatch.delenv("CI", raising=False)
    GraylogDeploy().deploy_tenant([_rule()], _tenant(token="$GRAYLOG_TOKEN"), RELEASE)
    assert codes == ["tenant_failed"]
    assert _failed()


def test_the_client_session_follows_the_tenant_ssl() -> None:
    assert GraylogClient(URL, "t", tenant=TENANT, verify_ssl=False).session.verify is False


def test_api_error_properties() -> None:
    error = GraylogApiError("PUT", "/x", 400, "", {"title": ["empty"], "config": ["bad", "worse"]})
    assert error.invalid and not error.immutable and not error.in_use
    assert error.detail == "config: bad; worse | title: empty"
    assert GraylogApiError("DELETE", "/x", 409, "depends on 2 definitions").in_use
    assert not GraylogApiError("PUT", "/x", 400, "depends on 2 definitions").in_use
    assert GraylogApiError("PUT", "/x", 404, "gone").not_found
    assert str(GraylogApiError("GET", "/x", 500, "")).endswith("no detail given")


def test_a_non_json_error_is_described() -> None:
    client = GraylogClient(URL, "t", tenant=TENANT)
    response = requests.Response()
    response.status_code = 502
    response._content = b"<html><title>Bad Gateway</title></html>"
    response.headers["Content-Type"] = "text/html"
    client.session.request = lambda *args, **kwargs: response  # type: ignore[method-assign]
    with pytest.raises(GraylogApiError) as caught:
        client.request("GET", "/api/system")
    assert "Bad Gateway" in caught.value.detail


def test_the_version_is_cached_by_the_client() -> None:
    fake = FakeGraylog("7.2.2")
    client = GraylogClient(URL, "t", tenant=TENANT)
    client.session.request = fake.request  # type: ignore[method-assign]
    assert client.version() == (7, 2, 2)
    assert client.version() == (7, 2, 2)
    assert len(fake.calls) == 1
    with pytest.raises(GraylogTenantError):
        fake_old = FakeGraylog("6.2.0")
        old = GraylogClient(URL, "t", tenant=TENANT)
        old.session.request = fake_old.request  # type: ignore[method-assign]
        old.version()


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"id": SAMPLE_ID.upper()}, SAMPLE_ID),
        ({"id": SAMPLE_ID}, SAMPLE_ID),
        ({"id": "123"}, None),
        ({}, None),
        ([SAMPLE_ID], None),
    ],
)
def test_returned_id(payload: Any, expected: str | None) -> None:
    assert returned_id(payload) == expected


@pytest.mark.parametrize(
    ("value", "ok"),
    [(SAMPLE_ID, True), (SAMPLE_ID.upper(), False), ("123", False), (123, False)],
)
def test_graylog_ids_in_state_are_24_lower_case_hex(value: object, ok: bool) -> None:
    if ok:
        assert normalise_external_id("graylog", value) == value
    else:
        with pytest.raises(DeploymentStateError):
            normalise_external_id("graylog", value)


def test_deploy_skips_rules_without_a_graylog_block(tide_corpus_repo: Path) -> None:
    del tide_corpus_repo
    GraylogDeploy().deploy([])
    assert not _failed()
