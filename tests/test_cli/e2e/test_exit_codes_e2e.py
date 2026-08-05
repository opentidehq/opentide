"""CLI E2E: exit code behaviour."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.cli_e2e


def test_validation_warning_exits_zero_without_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.exit_codes import validation_exit_code

    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    assert validation_exit_code(strict=False) == 0
    assert validation_exit_code(strict=True) == 1


def test_cli_exit_policy_never_returns_19(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.exit_codes import deployment_exit_code, validation_exit_code
    from opentide.deployment.ci import CIEnvironment

    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.setenv("DEPLOYMENT_WARNING_RAISED", "1")
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED", raising=False)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )
    assert validation_exit_code() != 19
    assert deployment_exit_code() != 19
