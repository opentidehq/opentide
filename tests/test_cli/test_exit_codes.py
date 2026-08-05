"""CI-aware CLI exit code helpers."""

from __future__ import annotations

import os

import pytest

from opentide.cli import exit_codes


def test_exit_on_validation_errors_raises_when_flag_set() -> None:
    os.environ["VALIDATION_ERROR_RAISED"] = "1"
    try:
        with pytest.raises(SystemExit) as exc:
            exit_codes.exit_on_validation_errors()
        assert exc.value.code == 1
    finally:
        os.environ.pop("VALIDATION_ERROR_RAISED", None)


def test_exit_on_validation_errors_noop_when_unset() -> None:
    os.environ.pop("VALIDATION_ERROR_RAISED", None)
    exit_codes.exit_on_validation_errors()


def test_exit_on_deployment_errors_raises_when_flag_set() -> None:
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    try:
        with pytest.raises(SystemExit) as exc:
            exit_codes.exit_on_deployment_errors()
        assert exc.value.code == 1
    finally:
        os.environ.pop("DEPLOYMENT_ERROR_RAISED", None)


def test_validation_exit_code_strict_fails_on_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    assert exit_codes.validation_exit_code(strict=True) == 1
    assert exit_codes.validation_exit_code(strict=False) == 0


def test_validation_outcome_never_uses_exit_19(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    outcome = exit_codes.validation_outcome()
    assert outcome.failed is False
    assert outcome.warned is True
    assert outcome.exit_code == 0
    assert outcome.exit_code != 19


def test_deployment_outcome_error_marks_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_ERROR_RAISED", "1")
    monkeypatch.delenv("DEPLOYMENT_WARNING_RAISED", raising=False)
    outcome = exit_codes.deployment_outcome()
    assert outcome.failed is True
    assert outcome.exit_code == 1
    assert exit_codes.deployment_exit_code() == 1


def test_deployment_warnings_do_not_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED", raising=False)
    monkeypatch.setenv("DEPLOYMENT_WARNING_RAISED", "1")
    outcome = exit_codes.deployment_outcome()
    assert outcome.failed is False
    assert outcome.warned is True
    assert outcome.exit_code == 0
