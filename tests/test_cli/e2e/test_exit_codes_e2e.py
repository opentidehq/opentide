"""CLI E2E: GitLab exit code behaviour."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.cli_e2e


def test_gitlab_validation_warning_exits_19(invoke_cli, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.setenv("VALIDATION_ERROR_RAISED", "")

    from opentide.cli.exit_codes import exit_on_validation_warnings

    with pytest.raises(SystemExit) as exc:
        exit_on_validation_warnings()
    assert exc.value.code == 19
