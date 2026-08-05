"""CI-aware CLI exit code helpers."""

from __future__ import annotations

import os

import pytest

from opentide.cli import exit_codes
from opentide.deployment.ci import CIEnvironment


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


def test_exit_on_validation_warnings_gitlab_soft_fail(monkeypatch: pytest.MonkeyPatch) -> None:

    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )
    with pytest.raises(SystemExit) as exc:
        exit_codes.exit_on_validation_warnings()
    assert exc.value.code == 19


def test_exit_on_deployment_warnings_non_gitlab_no_exit(monkeypatch: pytest.MonkeyPatch) -> None:

    monkeypatch.setenv("DEPLOYMENT_WARNING_RAISED", "1")
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitHubActions,
    )
    exit_codes.exit_on_deployment_warnings()


def test_validation_exit_code_strict_fails_on_local_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.setattr(CIEnvironment, "_check_ci_environment", lambda self: None)
    assert exit_codes.validation_exit_code(strict=True) == 1
    assert exit_codes.validation_exit_code(strict=False) == 0


def test_validation_outcome_separates_failed_from_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )
    outcome = exit_codes.validation_outcome()
    assert outcome.failed is False
    assert outcome.warned is True
    assert outcome.exit_code == 19


def test_deployment_outcome_error_marks_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_ERROR_RAISED", "1")
    monkeypatch.delenv("DEPLOYMENT_WARNING_RAISED", raising=False)
    outcome = exit_codes.deployment_outcome()
    assert outcome.failed is True
    assert outcome.exit_code == 1
    assert exit_codes.deployment_exit_code() == 1
