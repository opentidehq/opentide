"""CLI exit code helpers."""

from __future__ import annotations

import pytest

from opentide.cli import exit_codes


def test_exit_on_validation_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VALIDATION_ERROR_RAISED", "True")
    with pytest.raises(SystemExit) as exc:
        exit_codes.exit_on_validation_errors()
    assert exc.value.code == 1


def test_exit_on_deployment_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_ERROR_RAISED", "True")
    with pytest.raises(SystemExit):
        exit_codes.exit_on_deployment_errors()


def test_exit_on_validation_warnings_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VALIDATION_WARNING_RAISED", raising=False)
    exit_codes.exit_on_validation_warnings()
