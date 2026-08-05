"""CLI deploy service behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import DetectionPlatform
from opentide.cli.exit_codes import CiOutcome
from opentide.cli.services import deploy as deploy_service
from opentide.deployment.ci import CIEnvironment

CLEAN_OUTCOME = CiOutcome(exit_code=0, failed=False, warned=False)


def test_run_deploy_skips_when_platform_has_no_rules() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
    ):
        result = deploy_service.run_deploy(ctx, platform=DetectionPlatform.splunk)
    assert result["status"] == "skipped"


@pytest.mark.parametrize("json_output", [False, True])
def test_run_deploy_empty_plan_github_actions_warning(
    monkeypatch: pytest.MonkeyPatch, json_output: bool
) -> None:
    ctx = CliContext(json_output=json_output)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitHubActions,
    )
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={}),
        patch.object(deploy_service.get_stdout_console(), "print") as mock_print,
    ):
        result = deploy_service.run_deploy(ctx)
    assert result["status"] == "skipped"
    if json_output:
        # The annotation would corrupt the single-document JSON contract.
        mock_print.assert_not_called()
    else:
        assert "::warning::" in mock_print.call_args.args[0]


def test_run_deploy_empty_plan_gitlab_returns_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = CliContext(json_output=True)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={}),
    ):
        result = deploy_service.run_deploy(ctx)
    assert result["_exit_code"] == 19


def test_run_deploy_dry_run_collects_payloads() -> None:
    ctx = CliContext(json_output=True)
    deployer = MagicMock()
    preview = [{"uuid": "u1"}]
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.deployment.preview.preview_platform_deployment", return_value=preview),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr = {"sentinel": deployer}
        result = deploy_service.run_deploy(ctx, dry_run=True)
    assert result["status"] == "completed"
    assert result["dry_run"] is True
    assert result["payloads"] == {"sentinel": preview}
    deployer.deploy.assert_not_called()


def test_run_deploy_invokes_deployer() -> None:
    ctx = CliContext(json_output=True)
    deployer = MagicMock()
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr = {"sentinel": deployer}
        result = deploy_service.run_deploy(ctx)
    deployer.deploy.assert_called_once()
    assert result["deployed"] == ["sentinel"]
    assert result["status"] == "completed"
    assert "warnings" not in result


def test_run_deploy_warning_marks_result_with_warnings() -> None:
    ctx = CliContext(json_output=True)
    warned = CiOutcome(exit_code=19, failed=False, warned=True)
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=warned),
    ):
        mock_tide.return_value.mdr = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx)
    assert result["status"] == "completed"
    assert result["_exit_code"] == 19
    assert result["warnings"]


def test_run_deploy_error_marks_result_failed() -> None:
    ctx = CliContext(json_output=True)
    errored = CiOutcome(exit_code=1, failed=True, warned=False)
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=errored),
    ):
        mock_tide.return_value.mdr = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
