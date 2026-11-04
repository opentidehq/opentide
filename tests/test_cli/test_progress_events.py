"""``OPENTIDE_PROGRESS=json``: NDJSON progress events on stderr, stdout unchanged (#756)."""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import Result
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.test_query_cli import StandIn, query, splunk

from opentide.core import progress_events

__all__ = ["query", "splunk"]  # fixtures, imported for this module's tests

PROGRESS = {"OPENTIDE_PROGRESS": "json"}


def _events(stderr: str) -> list[dict[str, Any]]:
    """Every line of *stderr* that is a progress event; log lines are left out."""
    found: list[dict[str, Any]] = []
    for line in stderr.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("event") in {"progress", "tenant"}:
            found.append(value)
    return found


def _one_document(result: Result) -> dict[str, Any]:
    """Stdout is exactly one JSON document, ending in one newline: the contract holds."""
    assert result.stdout.endswith("}\n") and result.stdout.count("\n") == 1, result.stdout
    return parse_cli_json(result)


# --- the module ----------------------------------------------------------------------


def test_events_are_written_only_when_asked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("OPENTIDE_PROGRESS", raising=False)
    progress_events.progress("schemas", 1, 6)
    assert capsys.readouterr().err == ""
    for value in ("1", "0", "true"):
        monkeypatch.setenv("OPENTIDE_PROGRESS", value)
        progress_events.progress("schemas", 1, 6)
        assert capsys.readouterr().err == ""
    monkeypatch.setenv("OPENTIDE_PROGRESS", " JSON ")
    progress_events.progress("schemas", 3, 6)
    progress_events.tenant("sentinel", "prod", ok=True, rows=120, elapsed_ms=1800)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert [json.loads(line) for line in captured.err.splitlines()] == [
        {"event": "progress", "step": "schemas", "done": 3, "total": 6},
        {
            "event": "tenant",
            "platform": "sentinel",
            "tenant": "prod",
            "status": "ok",
            "rows": 120,
            "elapsed_ms": 1800,
        },
    ]


def test_a_sink_receives_the_events_instead_of_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPENTIDE_PROGRESS", "json")
    received: list[dict[str, Any]] = []
    with progress_events.sink(received.append):
        progress_events.tenant("splunk", "lab", ok=False, rows=0, elapsed_ms=5, label="q1")
    progress_events.progress("after", 1, 1)
    assert received == [
        {
            "event": "tenant",
            "platform": "splunk",
            "tenant": "lab",
            "status": "failed",
            "rows": 0,
            "elapsed_ms": 5,
            "label": "q1",
        }
    ]
    assert [json.loads(line)["step"] for line in capsys.readouterr().err.splitlines()] == ["after"]


def test_a_closed_stderr_is_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENTIDE_PROGRESS", "json")
    closed = io.StringIO()
    closed.close()
    monkeypatch.setattr("sys.stderr", closed)
    progress_events.progress("schemas", 1, 1)


def test_a_ticker_reports_in_batches_and_always_the_last_unit() -> None:
    received: list[dict[str, Any]] = []
    with progress_events.sink(received.append):
        ticker = progress_events.Ticker("objects", 100)
        for _ in range(100):
            ticker.advance()
        small = progress_events.Ticker("objects", 3)
        for _ in range(3):
            small.advance()
    big = [event["done"] for event in received if event["total"] == 100]
    assert big == list(range(5, 101, 5))
    assert [event["done"] for event in received if event["total"] == 3] == [1, 2, 3]


def test_a_ticker_with_nobody_listening_sends_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("OPENTIDE_PROGRESS", raising=False)
    ticker = progress_events.Ticker("objects", 2)
    ticker.advance()
    ticker.advance()
    assert capsys.readouterr().err == ""


# --- the commands ----------------------------------------------------------------------


def test_validate_reports_objects_on_stderr_and_one_document_on_stdout(
    invoke_cli: Callable[..., Result],
) -> None:
    result = invoke_cli("validate", extra_env=PROGRESS)
    document = _one_document(result)
    assert document["command"] == "validate"
    events = _events(result.stderr)
    objects = [event for event in events if event["step"] == "objects"]
    assert objects, result.stderr
    total = objects[-1]["total"]
    assert total == document["summary"]["objects"]
    assert objects[-1]["done"] == total
    assert [event["done"] for event in objects] == sorted(event["done"] for event in objects)
    assert any(event["step"] == "queries" for event in events)


def test_validate_query_offline_reports_its_queries(invoke_cli: Callable[..., Result]) -> None:
    """The offline check sent no event, though the documentation lists `validate query`."""
    result = invoke_cli("validate", "query", extra_env=PROGRESS)
    document = _one_document(result)
    queries = document["summary"]["queries"]
    assert queries
    assert _events(result.stderr) == [
        {"event": "progress", "step": "queries", "done": queries, "total": queries}
    ]


def test_without_the_variable_validate_writes_no_event(invoke_cli: Callable[..., Result]) -> None:
    result = invoke_cli("validate")
    _one_document(result)
    assert _events(result.stderr) == []


def test_generate_reports_each_phase(invoke_cli: Callable[..., Result]) -> None:
    result = invoke_cli("generate", "schemas", "templates", extra_env=PROGRESS)
    document = assert_json_ok(result)
    assert result.stdout.count("\n") == 1
    events = _events(result.stderr)
    assert [(event["step"], event["done"], event["total"]) for event in events] == [
        ("schemas", 1, 2),
        ("templates", 2, 2),
    ]
    assert [step["name"] for step in document["steps"]] == ["schemas", "templates"]


def test_query_reports_each_tenant(query: Callable[..., Result], splunk: StandIn) -> None:
    splunk.refuse.add("prod")
    result = query("--tenant", "all", "--since", "7d", "index=main", extra_env=PROGRESS)
    document = _one_document(result)
    assert result.exit_code == 1
    tenants = [event for event in _events(result.stderr) if event["event"] == "tenant"]
    assert [(e["platform"], e["tenant"], e["status"], e["rows"]) for e in tenants] == [
        ("splunk", "lab", "ok", 2),
        ("splunk", "prod", "failed", 0),
    ]
    assert all(isinstance(event["elapsed_ms"], int) for event in tenants)
    assert [r["tenant"] for r in document["results"]] == ["lab", "prod"]


def test_deploy_dry_run_reports_each_platform(
    invoke_cli: Callable[..., Result], tide_corpus_repo: Path
) -> None:
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--strategy",
        "PREVIEW,RELEASE",
        "--all",
        "--skip-promotion",
        extra_env=PROGRESS,
    )
    document = _one_document(result)
    events = _events(result.stderr)
    planned = list(document["plan"])
    assert planned, document
    assert [(event["step"], event["done"], event["total"]) for event in events] == [
        (system, position, len(planned)) for position, system in enumerate(planned, start=1)
    ]
