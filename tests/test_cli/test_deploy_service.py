"""CLI deploy service behaviour."""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import DetectionPlatform
from opentide.cli.exit_codes import CiOutcome
from opentide.cli.services import deploy as deploy_service
from opentide.deployment.ci import CIEnvironment

CLEAN_OUTCOME = CiOutcome(exit_code=0, failed=False, warned=False)
SPLUNK_TOML = ".opentide/configurations/platforms/splunk.toml"


@pytest.fixture(autouse=True)
def tenantless() -> Iterator[MagicMock]:
    """Every platform has a tenant unless a test says otherwise."""
    with patch("opentide.platforms.enabled.systems_without_tenants", return_value=[]) as mock:
        yield mock


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


def test_run_deploy_empty_plan_gitlab_exits_cleanly(
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
    assert result["status"] == "skipped"
    assert result.get("_exit_code", 0) == 0


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
        mock_tide.return_value.mdr_for.return_value = {"sentinel": deployer}
        result = deploy_service.run_deploy(ctx, dry_run=True)
    assert result["status"] == "completed"
    assert result["dry_run"] is True
    assert result["payloads"] == {"sentinel": preview}
    assert result["deployed"] == ["sentinel"]
    assert "missing_tenants" not in result
    assert "warnings" not in result
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
        mock_tide.return_value.mdr_for.return_value = {"sentinel": deployer}
        result = deploy_service.run_deploy(ctx)
    (requested,) = mock_tide.return_value.mdr_for.call_args.args
    assert list(requested) == ["sentinel"]
    deployer.deploy.assert_called_once()
    assert result["deployed"] == ["sentinel"]
    assert result["status"] == "completed"
    assert "warnings" not in result


def test_run_deploy_reports_an_engine_that_fails_to_load() -> None:
    """A broken engine in the plan was an uncaught exception and a traceback."""
    ctx = CliContext(json_output=True)
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
    ):
        mock_tide.return_value.mdr_for.side_effect = Exception(
            "PLATFORM ENGINE IMPORT ERROR: sentinel"
        )
        result = deploy_service.run_deploy(ctx)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert "sentinel" in str(result["message"])
    assert result["deployed"] == []


def test_run_deploy_warning_marks_result_with_warnings() -> None:
    ctx = CliContext(json_output=True)
    warned = CiOutcome(exit_code=0, failed=False, warned=True)
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
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx)
    assert result["status"] == "completed"
    assert result["_exit_code"] == 0
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
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1


def test_run_deploy_invalid_plan_returns_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = CliContext(json_output=True)
    monkeypatch.setenv("DEPLOYMENT_PLAN", "None")
    with patch("opentide.core.registry.OpenTide.reload"):
        result = deploy_service.run_deploy(ctx, dry_run=True)
    assert result["status"] == "failed"
    assert "Unsupported deployment plan" in str(result["message"])
    assert result["_exit_code"] == 1


def test_run_deploy_dry_run_skips_production_promotion() -> None:
    from opentide.models.deployment_enums import DeploymentStrategy

    ctx = CliContext(json_output=True)
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=DeploymentStrategy.PRODUCTION,
        ),
        patch("opentide.deployment.modified_mdr_files") as mock_modified,
        patch("opentide.mutation.promotion.PromoteMDR") as mock_promote,
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.deployment.preview.preview_platform_deployment", return_value=[]),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx, dry_run=True)
    mock_modified.assert_not_called()
    mock_promote.assert_not_called()
    assert result["dry_run"] is True


def test_run_deploy_local_debug_skips_production_promotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentide.models.deployment_enums import DeploymentStrategy

    ctx = CliContext(json_output=True)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.LocalDebug,
    )
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=DeploymentStrategy.PRODUCTION,
        ),
        patch("opentide.deployment.modified_mdr_files") as mock_modified,
        patch("opentide.mutation.promotion.PromoteMDR") as mock_promote,
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx, dry_run=False)
    mock_modified.assert_not_called()
    mock_promote.assert_not_called()
    assert result["status"] == "completed"


def test_run_deploy_without_tenants_fails_before_loading_engines(tenantless: MagicMock) -> None:
    """#314: the resolver's bare ``raise Exception`` reached the user as a traceback."""
    ctx = CliContext(json_output=True)
    tenantless.return_value = ["splunk"]
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"], "splunk": ["u2"]},
        ),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload") as mock_reload,
        patch("opentide.platforms.enabled.platform_config_path", return_value=SPLUNK_TOML),
    ):
        result = deploy_service.run_deploy(ctx)
    tenantless.assert_called_once_with({"sentinel": ["u1"], "splunk": ["u2"]})
    mock_tide.assert_not_called()
    mock_reload.assert_not_called()
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert result["message"] == f"Cannot deploy: splunk has no tenants configured in {SPLUNK_TOML}"
    assert result["advice"] == f"add (or uncomment) a [[tenants]] entry in {SPLUNK_TOML}"
    assert result["missing_tenants"] == {"splunk": SPLUNK_TOML}
    assert result["deployed"] == []
    assert result["plan"] == {"sentinel": ["u1"], "splunk": ["u2"]}


def test_run_deploy_dry_run_does_not_claim_a_platform_without_tenants(
    tenantless: MagicMock,
) -> None:
    ctx = CliContext(json_output=True)
    tenantless.return_value = ["splunk"]
    deployers = {"sentinel": MagicMock(), "splunk": MagicMock()}
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"], "splunk": ["u2"]},
        ),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.deployment.preview.preview_platform_deployment", return_value=[]),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
        patch("opentide.platforms.enabled.platform_config_path", return_value=SPLUNK_TOML),
    ):
        mock_tide.return_value.mdr_for.return_value = deployers
        result = deploy_service.run_deploy(ctx, dry_run=True)
    assert result["status"] == "completed"
    assert result["_exit_code"] == 0
    assert result["deployed"] == ["sentinel"]
    assert set(result["payloads"]) == {"sentinel", "splunk"}
    assert result["missing_tenants"] == {"splunk": SPLUNK_TOML}
    assert result["advice"] == f"add (or uncomment) a [[tenants]] entry in {SPLUNK_TOML}"
    assert result["warnings"] == [
        f"splunk has no tenants configured in {SPLUNK_TOML}, so a real deploy would stop"
    ]
    for deployer in deployers.values():
        deployer.deploy.assert_not_called()


def test_run_deploy_dry_run_keeps_rule_warnings_next_to_tenant_warnings(
    tenantless: MagicMock,
) -> None:
    ctx = CliContext(json_output=True)
    tenantless.return_value = ["splunk"]
    warned = CiOutcome(exit_code=0, failed=False, warned=True)
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", return_value={"splunk": ["u2"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.deployment.preview.preview_platform_deployment", return_value=[]),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=warned),
        patch("opentide.platforms.enabled.platform_config_path", return_value=SPLUNK_TOML),
    ):
        mock_tide.return_value.mdr_for.return_value = {"splunk": MagicMock()}
        result = deploy_service.run_deploy(ctx, dry_run=True)
    assert result["deployed"] == []
    assert result["warnings"] == [
        f"splunk has no tenants configured in {SPLUNK_TOML}, so a real deploy would stop",
        "Some rules reported deployment warnings",
    ]


def test_run_deploy_empty_exception_does_not_advise_full_plan() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", side_effect=KeyError()),
    ):
        result = deploy_service.run_deploy(ctx, dry_run=True)
    assert result["status"] == "failed"
    assert "FULL" not in str(result["message"])
    assert "KeyError" in str(result["message"])


SUBFOLDER_WARNING = "1 rule file(s) in subfolders of objects/rules are not deployed"
DEPLOY_WARNING = "Some rules reported deployment warnings"


@pytest.mark.parametrize(
    ("plan", "platform", "engine_error", "status", "warnings"),
    [
        pytest.param({}, None, None, "skipped", [SUBFOLDER_WARNING], id="nothing-matched"),
        pytest.param(
            {"sentinel": ["u1"]},
            DetectionPlatform.splunk,
            None,
            "skipped",
            [SUBFOLDER_WARNING],
            id="platform-not-planned",
        ),
        pytest.param(KeyError("plan"), None, None, "failed", [SUBFOLDER_WARNING], id="plan-failed"),
        pytest.param(
            {"sentinel": ["u1"]},
            None,
            RuntimeError("engine"),
            "failed",
            [SUBFOLDER_WARNING],
            id="engine-failed",
        ),
        pytest.param(
            {"sentinel": ["u1"]},
            None,
            None,
            "completed",
            [SUBFOLDER_WARNING, DEPLOY_WARNING],
            id="completed",
        ),
    ],
)
def test_run_deploy_reports_plan_warnings_in_every_result(
    plan: dict[str, list[str]] | Exception,
    platform: DetectionPlatform | None,
    engine_error: Exception | None,
    status: str,
    warnings: list[str],
) -> None:
    """#312: a warning raised while planning must reach whichever result follows."""
    ctx = CliContext(json_output=True)
    warned = CiOutcome(exit_code=0, failed=False, warned=True)

    def _plan(*args: object, warnings: list[str], **kwargs: object) -> dict[str, list[str]]:
        warnings.append(SUBFOLDER_WARNING)
        if isinstance(plan, Exception):
            raise plan
        return plan

    with (
        patch("opentide.core.registry.OpenTide.reload"),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
            return_value=MagicMock(),
        ),
        patch("opentide.deployment.make_deploy_plan", side_effect=_plan) as mock_plan,
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=warned),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        if engine_error is not None:
            mock_tide.return_value.mdr_for.side_effect = engine_error
        result = deploy_service.run_deploy(ctx, platform=platform)
    mock_plan.assert_called_once()
    assert result["status"] == status
    assert result["warnings"] == warnings
