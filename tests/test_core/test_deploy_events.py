"""Rule events: what a deployer reports per rule, and how a platform's error reads (#675)."""

from __future__ import annotations

import pytest

from opentide.core import deploy_events
from opentide.core.deploy_events import RuleResult, deploying, describe_error


class _Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, str]] = []

    def rule_started(self, result: RuleResult) -> None:
        self.events.append(("started", result.id, result.status))

    def rule_finished(self, result: RuleResult) -> None:
        self.events.append(("finished", result.id, result.status))


class _AzureError(Exception):
    """An ``azure.core.exceptions.HttpResponseError``: ``status_code`` and a clean ``error``."""

    def __init__(self, message: str, status_code: int, clean: str) -> None:
        super().__init__(message)
        self.status_code = status_code

        class _Detail:
            pass

        self.error = _Detail()
        self.error.message = clean  # ty: ignore[unresolved-attribute]  # test double


class _Response:
    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> object:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _HttpError(Exception):
    """A ``requests.HTTPError``: the status and body are on ``response``."""

    def __init__(self, response: _Response) -> None:
        super().__init__(f"{response.status_code} Client Error")
        self.response = response


def _send(error: BaseException) -> None:
    """What a deployer's call into the platform does when it is refused."""
    raise error


def test_a_rule_that_returns_is_deployed_and_reported_twice() -> None:
    recorder = _Recorder()
    with deploy_events.listen(recorder), deploying("sentinel", "contoso", "u1", "Rule one"):
        pass
    assert recorder.events == [("started", "u1", "deployed"), ("finished", "u1", "deployed")]


def test_a_rule_that_raises_is_failed_with_the_platform_message_and_the_error_propagates() -> None:
    results: list[RuleResult] = []

    class _Keep(_Recorder):
        def rule_finished(self, result: RuleResult) -> None:
            results.append(result)

    error = _AzureError("(BadRequest) Bad query\nCode: BadRequest", 400, "Bad query")
    with (
        pytest.raises(_AzureError) as raised,
        deploy_events.listen(_Keep()),
        deploying("sentinel", "contoso", "u1", "Rule one"),
    ):
        _send(error)
    assert raised.value is error
    (result,) = results
    assert result.status == "failed"
    assert result.error == "HTTP 400: Bad query"
    assert result.seconds is not None


def test_a_failure_noted_inside_the_block_marks_the_rule_without_raising() -> None:
    results: list[RuleResult] = []

    class _Keep(_Recorder):
        def rule_finished(self, result: RuleResult) -> None:
            results.append(result)

    with deploy_events.listen(_Keep()), deploying("elastic", "t", "u1", "Rule one"):
        deploy_events.note_failure("HTTP 409:   version\nconflict")
        deploy_events.note_failure("a second failure does not replace the first")
    assert results[0].status == "failed"
    assert results[0].error == "HTTP 409: version conflict"


def test_a_skip_is_not_a_failure_and_a_failure_wins_over_a_skip() -> None:
    results: list[RuleResult] = []

    class _Keep(_Recorder):
        def rule_finished(self, result: RuleResult) -> None:
            results.append(result)

    with deploy_events.listen(_Keep()):
        with deploying("elastic", "t", "u1", "One"):
            deploy_events.note_skip("status DESIGN is inert")
        with deploying("elastic", "t", "u2", "Two"):
            deploy_events.note_failure("boom")
            deploy_events.note_skip("ignored")
        deploy_events.skipped("harfanglab", "t", "u3", "Three", "Sigma rule, YARA tenant")
        deploy_events.refused("defender_for_endpoint", "t", "u4", "Four", "external_id_missing")
    assert [(r.id, r.status) for r in results] == [
        ("u1", "skipped"),
        ("u2", "failed"),
        ("u3", "skipped"),
        ("u4", "failed"),
    ]
    assert results[0].reason == "status DESIGN is inert"
    assert results[3].error == "external_id_missing"


def test_helpers_outside_a_rule_block_do_nothing() -> None:
    deploy_events.note_failure("nobody is sending a rule")
    deploy_events.note_skip("nobody is sending a rule")
    assert not deploy_events.is_listening()


def test_listening_is_scoped_to_the_block() -> None:
    recorder = _Recorder()
    with deploy_events.listen(recorder):
        assert deploy_events.is_listening()
    assert not deploy_events.is_listening()
    with deploying("sentinel", None, "u1", "After"):
        pass
    assert recorder.events == []


def test_the_row_a_result_carries_in_json() -> None:
    with deploying("sentinel", "contoso", "u1", "Rule one", action="update") as scope:
        scope.result.seconds = 0.12345
    row = scope.result.to_dict()
    assert row == {
        "platform": "sentinel",
        "tenant": "contoso",
        "id": "u1",
        "name": "Rule one",
        "status": "deployed",
        "action": "update",
        "seconds": 0.123,
        "error": None,
        "reason": None,
    }


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        pytest.param(
            _AzureError(
                "(BadRequest) Bad query\nCode: BadRequest\nMessage: Bad query", 400, "Bad query"
            ),
            "HTTP 400: Bad query",
            id="azure error uses the service's own message",
        ),
        pytest.param(
            _HttpError(_Response(409, {"message": "rule exists"})),
            "HTTP 409: rule exists",
            id="requests response body message",
        ),
        pytest.param(
            _HttpError(_Response(500, {"error": {"message": "internal"}})),
            "HTTP 500: internal",
            id="nested error message",
        ),
        pytest.param(
            _HttpError(_Response(502, ValueError("not json"))),
            "HTTP 502: 502 Client Error",
            id="a body that is not json falls back to the exception text",
        ),
        pytest.param(
            Exception("(BadRequest) lost its status\nCode: BadRequest"),
            "Exception: lost its status",
            id="no status: type and first line, Azure's code prefix dropped",
        ),
        pytest.param(
            type("SplunkHTTPError", (Exception,), {"status": 409})("rule exists"),
            "HTTP 409: rule exists",
            id="the Splunk SDK's status attribute",
        ),
        pytest.param(KeyError("missing"), "KeyError: 'missing'", id="plain exception"),
        pytest.param(RuntimeError(), "RuntimeError", id="empty message"),
        pytest.param(KeyboardInterrupt(), "interrupted", id="ctrl-c"),
    ],
)
def test_describe_error(exc: BaseException, expected: str) -> None:
    assert describe_error(exc) == expected


def test_a_page_of_html_does_not_fill_the_log() -> None:
    error = describe_error(RuntimeError("<html>" + "x" * 5000))
    assert len(error) <= deploy_events.MAX_ERROR_LENGTH
    assert error.endswith("…")


def test_a_listener_that_raises_on_start_leaves_no_scope_behind() -> None:
    """A stale scope would take the next rule's failure notes."""

    class _Broken(_Recorder):
        def rule_started(self, result: RuleResult) -> None:
            raise OSError("stderr is closed")

    with (
        deploy_events.listen(_Broken()),
        pytest.raises(OSError),
        deploying("sentinel", "contoso", "u1", "Rule one"),
    ):
        pass  # not reached: entering the block raises
    assert deploy_events._current == []  # ty: ignore[unresolved-attribute]  # private, on purpose

    results: list[RuleResult] = []

    class _Keep(_Recorder):
        def rule_finished(self, result: RuleResult) -> None:
            results.append(result)

    with deploy_events.listen(_Keep()), deploying("sentinel", "contoso", "u2", "Rule two"):
        deploy_events.note_failure("belongs to rule two")
    assert [(r.id, r.error) for r in results] == [("u2", "belongs to rule two")]
