"""CLI structured output helpers."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.output import emit, emit_error, emit_success


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
    assert payload == {"ok": False, "error": "boom"}
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
