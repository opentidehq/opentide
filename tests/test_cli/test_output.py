"""CLI structured output helpers."""

from __future__ import annotations

import json

import pytest

from opentide.cli.context import CliContext
from opentide.cli.output import (
    CommandResult,
    emit,
    emit_error,
    emit_result,
    emit_success,
    emit_usage_error,
    envelope,
)
from opentide.cli.ui.contract import NextAction


def test_emit_json_output(capsys) -> None:
    ctx = CliContext(json_output=True)
    emit(ctx, {"status": "ok"})
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "ok"


def test_emit_nonzero_exit_raises() -> None:
    ctx = CliContext(json_output=False)
    with pytest.raises(SystemExit) as exc:
        emit(ctx, {}, exit_code=2)
    assert exc.value.code == 2


def test_emit_error_json_mode(capsys) -> None:
    ctx = CliContext(json_output=True)
    with pytest.raises(SystemExit) as exc:
        emit_error(ctx, "boom", exit_code=3)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    # The keys scripts already read keep their names, types and meaning.
    assert {key: payload[key] for key in ("ok", "status", "message", "error")} == {
        "ok": False,
        "status": "failed",
        "message": "boom",
        "error": "boom",
    }
    assert payload["schema_version"] == 1
    assert payload["exit_code"] == 3
    assert payload["summary"] == {}
    assert payload["next_actions"] == []
    assert payload["failure"] == {
        "code": "command_failed",
        "message": "boom",
        "argument": None,
        "suggestion": None,
        "crash_log": None,
    }
    assert isinstance(payload["duration_ms"], int)
    assert exc.value.code == 3


def test_emit_error_text_mode(capsys) -> None:
    ctx = CliContext(json_output=False)
    with pytest.raises(SystemExit) as exc:
        emit_error(ctx, "boom")
    captured = capsys.readouterr()
    assert captured.err == "error: boom\n"
    assert "FATAL" not in captured.out + captured.err
    assert exc.value.code == 1


def test_emit_usage_error_suggests_the_closest_choice(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        emit_usage_error(
            CliContext(json_output=True),
            "Unknown section: rulez",
            argument="section",
            value="rulez",
            choices=("rules", "threats"),
        )
    assert exc.value.code == 2
    failure = json.loads(capsys.readouterr().out)["failure"]
    assert failure["code"] == "usage_invalid_choice"
    assert failure["argument"] == "section"
    assert failure["suggestion"] == "rules"


def test_emit_usage_error_text_mode_prints_the_suggestion(capsys) -> None:
    with pytest.raises(SystemExit):
        emit_usage_error(
            CliContext(),
            "Unknown section: rulez",
            argument="section",
            value="rulez",
            choices=("rules", "threats"),
        )
    assert capsys.readouterr().err == (
        "error: Unknown section: rulez\n  help: did you mean 'rules'?\n"
    )


def test_emit_success_json_and_text_modes(capsys) -> None:
    json_ctx = CliContext(json_output=True)
    emit_success(json_ctx, {"message": "done", "count": 2})
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["count"] == 2

    text_ctx = CliContext(json_output=False)
    emit_success(text_ctx, {"message": "finished"})


def test_emit_result_prints_warnings_before_the_outcome(capsys) -> None:
    ctx = CliContext(json_output=False)
    emit_result(
        ctx,
        CommandResult(
            message="Nothing matched",
            status="skipped",
            warnings=("Check the selected plan",),
        ),
    )
    captured = capsys.readouterr()
    assert captured.err == "warning: Check the selected plan\n"
    assert captured.out == "Skipped: Nothing matched\n"


def test_nonzero_exit_with_non_failed_status_is_not_an_error(capsys) -> None:
    ctx = CliContext(json_output=False)
    result = CommandResult.from_payload(
        {
            "status": "skipped",
            "message": "No rules matched this deployment plan",
            "_exit_code": 2,
            "_failure_code": "no_tenant_reached",
        }
    )
    assert result.ok is True
    assert result.failure is not None and result.failure.code == "no_tenant_reached"
    with pytest.raises(SystemExit) as exc:
        emit_result(ctx, result)
    captured = capsys.readouterr()
    assert captured.out == "Skipped: No rules matched this deployment plan\n"
    assert "error" not in captured.err
    assert exc.value.code == 2


def test_quiet_prints_only_the_outcome(capsys) -> None:
    ctx = CliContext(quiet=True)
    emit_result(
        ctx,
        CommandResult(
            message="Catalogue lint found issues",
            status="issues",
            data={"advice": "rename the files"},
            warnings=("one warning",),
            next_actions=(NextAction("opentide lint --fix", "rename 2 files"),),
        ),
    )
    captured = capsys.readouterr()
    assert captured.out == "! Catalogue lint found issues\n"
    assert captured.err == ""


def test_failure_is_null_exactly_when_the_exit_code_is_zero(capsys) -> None:
    ctx = CliContext(json_output=True)
    emit_result(ctx, CommandResult.from_payload({"message": "fine"}))
    assert json.loads(capsys.readouterr().out)["failure"] is None
    with pytest.raises(SystemExit):
        emit_result(
            ctx,
            CommandResult.from_payload({"status": "issues", "message": "x", "_exit_code": 1}),
        )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "issues_found"


def test_from_payload_moves_private_keys_into_the_envelope(capsys) -> None:
    result = CommandResult.from_payload(
        {
            "message": "Linted",
            "_summary": {"files": 3},
            "_next_actions": [{"command": "opentide lint --fix", "reason": "rename"}],
        }
    )
    emit_result(CliContext(json_output=True), result)
    payload = json.loads(capsys.readouterr().out)
    assert not [key for key in payload if key.startswith("_")]
    assert payload["summary"] == {"files": 3}
    assert payload["next_actions"] == [{"command": "opentide lint --fix", "reason": "rename"}]


def test_envelope_keeps_keys_the_payload_already_has() -> None:
    document = envelope({"ok": True, "summary": {"kept": 1}}, exit_code=0, command="info")
    assert document["summary"] == {"kept": 1}
    assert document["command"] == "info"
    assert document["failure"] is None


def test_from_payload_marks_failed_status() -> None:
    failed_status = CommandResult.from_payload(
        {"status": "failed", "message": "nope", "_exit_code": 1}
    )
    assert failed_status.ok is False
    completed = CommandResult.from_payload({"status": "completed", "_exit_code": 0})
    assert completed.ok is True
