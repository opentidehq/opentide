"""CLI E2E: GitLab exit code behaviour."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.cli_e2e


def test_gitlab_validation_warning_exits_19(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.exit_codes import exit_on_validation_warnings
    from opentide.deployment.ci import CIEnvironment

    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )

    with pytest.raises(SystemExit) as exc:
        exit_on_validation_warnings()
    assert exc.value.code == 19
