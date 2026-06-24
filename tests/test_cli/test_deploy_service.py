"""CLI deploy service behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import DetectionPlatform
from opentide.cli.services import deploy as deploy_service
from opentide.deployment.ci import CIEnvironment


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


def test_run_deploy_empty_plan_github_actions_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = CliContext(json_output=True)
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
    ):
        result = deploy_service.run_deploy(ctx)
    assert result["status"] == "empty"


def test_run_deploy_empty_plan_gitlab_exits(monkeypatch: pytest.MonkeyPatch) -> None:
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
        pytest.raises(SystemExit) as exc,
    ):
        deploy_service.run_deploy(ctx)
    assert exc.value.code == 19


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
        patch("opentide.cli.exit_codes.exit_on_deployment_errors"),
        patch("opentide.cli.exit_codes.exit_on_deployment_warnings"),
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
        patch("opentide.cli.exit_codes.exit_on_deployment_errors"),
        patch("opentide.cli.exit_codes.exit_on_deployment_warnings"),
    ):
        mock_tide.return_value.mdr = {"sentinel": deployer}
        result = deploy_service.run_deploy(ctx)
    deployer.deploy.assert_called_once()
    assert result["deployed"] == ["sentinel"]
