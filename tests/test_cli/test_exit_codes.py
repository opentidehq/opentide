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
