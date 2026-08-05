"""CLI structured output helpers."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.output import CommandResult, emit, emit_error, emit_result, emit_success


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
    assert payload == {
        "ok": False,
        "status": "failed",
        "message": "boom",
        "error": "boom",
    }
    assert exc.value.code == 3


def test_emit_error_text_mode() -> None:
    ctx = CliContext(json_output=False)
    with (
        patch("opentide.cli.output.emit_fatal") as mock_fatal,
        pytest.raises(SystemExit) as exc,
    ):
        emit_error(ctx, "boom")
    mock_fatal.assert_called_once_with("boom")
    assert exc.value.code == 1


def test_emit_success_json_and_text_modes(capsys) -> None:
    json_ctx = CliContext(json_output=True)
    emit_success(json_ctx, {"message": "done", "count": 2})
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["count"] == 2

    text_ctx = CliContext(json_output=False)
    emit_success(text_ctx, {"message": "finished"})


def test_emit_result_renders_skipped_and_warnings() -> None:
    ctx = CliContext(json_output=False)
    with (
        patch("opentide.cli.output.get_stdout_console") as stdout,
        patch("opentide.cli.output.get_console") as stderr,
    ):
        emit_result(
            ctx,
            CommandResult(
                message="Nothing matched",
                status="skipped",
                warnings=("Check the selected plan",),
            ),
        )
    stdout.return_value.print.assert_called_once()
    stderr.return_value.print.assert_called_once()


def test_nonzero_exit_with_non_failed_status_is_not_fatal() -> None:
    ctx = CliContext(json_output=False)
    result = CommandResult.from_payload(
        {
            "status": "skipped",
            "message": "No rules matched this deployment plan",
            "_exit_code": 2,
        }
    )
    assert result.ok is True
    with (
        patch("opentide.cli.output.emit_fatal") as mock_fatal,
        patch("opentide.cli.output.get_stdout_console") as stdout,
        patch("opentide.cli.output.get_console"),
        pytest.raises(SystemExit) as exc,
    ):
        emit_result(ctx, result)
    mock_fatal.assert_not_called()
    assert "SKIPPED" in stdout.return_value.print.call_args.args[0]
    assert exc.value.code == 2


def test_from_payload_marks_failed_status() -> None:
    failed_status = CommandResult.from_payload(
        {"status": "failed", "message": "nope", "_exit_code": 1}
    )
    assert failed_status.ok is False
    completed = CommandResult.from_payload({"status": "completed", "_exit_code": 0})
    assert completed.ok is True
