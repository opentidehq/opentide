"""Defender for Endpoint Graph client: the safer-configuration retry and error answers."""

from __future__ import annotations

import json
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
import requests
from structlog.testing import capture_logs

from opentide.core.errors import Errors
from opentide.platforms.defender_for_endpoint import client as mde

GRAPH = "https://graph.microsoft.com/beta/security"
RULES = GRAPH + "/rules/detectionRules"


def _response(status: int, body: bytes = b"", content_type: str = "application/json") -> Any:
    response = requests.Response()
    response.status_code = status
    response._content = body
    response.headers["Content-Type"] = content_type
    return response


def _graph_error(status: int, message: str) -> Any:
    return _response(status, json.dumps({"error": {"code": "x", "message": message}}).encode())


class _Session:
    """Answers each call with the next response and records the URLs."""

    def __init__(self, *answers: Any) -> None:
        self._answers = list(answers)
        self.urls: list[str] = []

    def _answer(self, url: str, **_kwargs: object) -> Any:
        self.urls.append(url)
        return self._answers.pop(0)

    post = patch = delete = _answer


def _service(session: _Session) -> Any:
    service = mde.DefenderForEndpointService.__new__(mde.DefenderForEndpointService)
    service.GRAPH_API_ENDPOINT = GRAPH
    service.DETECTION_RULES_ENDPOINT = RULES
    service.HUNTING_QUERY_ENDPOINT = GRAPH + "/runHuntingQuery"
    service.tenant_config = SimpleNamespace(name="Primary")
    service.verify = True
    service.session = session
    return service


def _rule() -> Any:
    rule = mde.DetectionRule
    template = rule.DetectionAction.AlertTemplate
    return rule(
        displayName="Rule",
        queryCondition=rule.QueryCondition(queryText="DeviceEvents"),
        schedule=rule.Schedule(period="1H"),
        detectionAction=rule.DetectionAction(
            alertTemplate=template(
                title="t",
                description="d",
                severity=mde.Severity.low,
                category="Execution",
                impactedAssets=[
                    template.ImpactedAsset(
                        odata_type="#microsoft.graph.security.impactedUserAsset",
                        identifier="accountUpn",
                    )
                ],
            ),
            responseActions=[],
        ),
    )


def test_the_safer_configuration_retry_creates_in_the_detection_rules_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry was posted to the Graph security root and could never succeed."""
    monkeypatch.delenv("DEPLOYMENT_WARNING_RAISED", raising=False)
    session = _Session(
        _graph_error(400, "accountUpn is not a column of the query"),
        _response(201, b'{"id": "42"}'),
    )

    assert _service(session).create_detection_rule(_rule()) == 42
    assert session.urls == [RULES, RULES]


_NOT_JSON = [
    pytest.param(_response(404), id="empty-404"),
    pytest.param(_response(502, b"<html>Bad Gateway</html>", "text/html"), id="html-502"),
]


def _raised_with_status(call: Callable[[], object], error: type[BaseException], status: int):
    with capture_logs() as logs, pytest.raises(error) as raised:
        call()
    assert not isinstance(raised.value, json.JSONDecodeError)
    assert any(f"Error Code {status}" in str(entry.get("detail")) for entry in logs), logs


@pytest.mark.parametrize("answer", _NOT_JSON)
def test_a_create_refused_without_json_reports_its_status(answer: Any) -> None:
    """``request.json()`` on the error body raised JSONDecodeError and lost the status."""
    session = _Session(answer, _response(answer.status_code, answer.content))
    _raised_with_status(
        lambda: _service(session).create_detection_rule(_rule()),
        Errors.DetectionRuleCreationFailed,
        answer.status_code,
    )


@pytest.mark.parametrize("answer", _NOT_JSON)
def test_an_update_refused_without_json_reports_its_status(answer: Any) -> None:
    _raised_with_status(
        lambda: _service(_Session(answer)).update_detection_rule(_rule(), 7),
        Errors.DetectionRuleUpdateFailed,
        answer.status_code,
    )


@pytest.mark.parametrize("answer", [*_NOT_JSON, pytest.param(_response(403), id="empty-403")])
def test_a_hunting_query_refused_without_json_reports_its_status(answer: Any) -> None:
    _raised_with_status(
        lambda: _service(_Session(answer)).run_hunting_query("DeviceEvents"),
        Exception,
        answer.status_code,
    )


def test_a_hunting_query_error_names_graphs_message() -> None:
    session = _Session(_graph_error(400, "Syntax error near 'whre'"))
    with pytest.raises(Exception, match="status 400: Syntax error near 'whre'"):
        _service(session).run_hunting_query("DeviceEvents | whre x")
