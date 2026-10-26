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
PREVIEW = ("PREVIEW",)
EMPTY_SELECTION = "No rule this run read has a status that maps to its strategies"


@pytest.fixture(autouse=True)
def _no_removed_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEPLOYMENT_PLAN", raising=False)


@pytest.fixture(autouse=True)
def tenantless() -> Iterator[MagicMock]:
    """Every platform has a tenant unless a test says otherwise."""
    with patch("opentide.platforms.enabled.systems_without_tenants", return_value=[]) as mock:
        yield mock


def test_run_deploy_skips_when_platform_has_no_rules() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
    ):
        result = deploy_service.run_deploy(
            ctx, strategies=PREVIEW, platform=DetectionPlatform.splunk
        )
    assert result["status"] == "skipped"


@pytest.mark.parametrize("json_output", [False, True])
def test_run_deploy_empty_selection_github_actions_warning(
    monkeypatch: pytest.MonkeyPatch, json_output: bool
) -> None:
    ctx = CliContext(json_output=json_output)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitHubActions,
    )
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={}),
        patch.object(deploy_service.get_stdout_console(), "print") as mock_print,
    ):
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
    assert result["status"] == "skipped"
    assert result["message"] == EMPTY_SELECTION
    if json_output:
        # The annotation would corrupt the single-document JSON contract.
        mock_print.assert_not_called()
    else:
        assert mock_print.call_args.args[0] == f"::warning::{EMPTY_SELECTION}"


def test_run_deploy_empty_selection_gitlab_exits_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = CliContext(json_output=True)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={}),
    ):
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
    assert result["status"] == "skipped"
    assert result.get("_exit_code", 0) == 0


def test_run_deploy_dry_run_collects_payloads() -> None:
    from opentide.models.deployment_enums import StatusStrategy

    ctx = CliContext(json_output=True)
    deployer = MagicMock()
    preview = [{"uuid": "u1"}]
    with (
        patch(
            "opentide.cli.services.deploy._tenant_targets", return_value={"Primary": ["u1"]}
        ) as targets,
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.deployment.preview.preview_platform_deployment", return_value=preview),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": deployer}
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW, dry_run=True)
    assert result["status"] == "completed"
    assert result["dry_run"] is True
    assert result["strategies"] == ["PREVIEW"]
    assert result["tenants"] == {"sentinel": {"Primary": ["u1"]}}
    targets.assert_called_once()
    assert targets.call_args.args[:3] == ("sentinel", ["u1"], (StatusStrategy.PREVIEW,))
    assert result["payloads"] == {"sentinel": preview}
    assert result["deployed"] == ["sentinel"]
    assert "missing_tenants" not in result
    assert "warnings" not in result
    deployer.deploy.assert_not_called()


def test_run_deploy_invokes_deployer() -> None:
    ctx = CliContext(json_output=True)
    deployer = MagicMock()
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": deployer}
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
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
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
    ):
        mock_tide.return_value.mdr_for.side_effect = Exception(
            "PLATFORM ENGINE IMPORT ERROR: sentinel"
        )
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert "sentinel" in str(result["message"])
    assert result["deployed"] == []


def test_run_deploy_reports_a_platform_that_fails_and_what_was_deployed() -> None:
    """A TypeError inside a deployer was retried as ``deploy(deployment=...)``.

    That signature exists on no engine, so its own TypeError escaped as a
    traceback in place of the real one; no result said which platforms had
    already been deployed.
    """
    ctx = CliContext(json_output=True)
    sentinel = MagicMock()
    splunk = MagicMock()
    splunk.deploy.side_effect = TypeError("'NoneType' object is not subscriptable")
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"], "splunk": ["u2"]},
        ),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.services.deploy._tenant_targets", return_value={}),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": sentinel, "splunk": splunk}
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert result["message"] == (
        "Deployment to splunk failed: TypeError: 'NoneType' object is not subscriptable"
    )
    assert result["deployed"] == ["sentinel"]
    assert result["plan"] == {"sentinel": ["u1"], "splunk": ["u2"]}
    splunk.deploy.assert_called_once()
    assert "deployment" not in splunk.deploy.call_args.kwargs


def test_run_deploy_warning_marks_result_with_warnings() -> None:
    ctx = CliContext(json_output=True)
    warned = CiOutcome(exit_code=0, failed=False, warned=True)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=warned),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
    assert result["status"] == "completed"
    assert result["_exit_code"] == 0
    assert result["warnings"]


def test_run_deploy_error_marks_result_failed() -> None:
    ctx = CliContext(json_output=True)
    errored = CiOutcome(exit_code=1, failed=True, warned=False)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=errored),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1


@pytest.mark.parametrize(
    ("value", "replacement"),
    [
        ("STAGING", "--strategy PREVIEW"),
        ("PRODUCTION", "--strategy RELEASE"),
        ("full", "--strategy PREVIEW --strategy RELEASE --all"),
        ("None", "--strategy PREVIEW or --strategy RELEASE"),
    ],
)
def test_run_deploy_refuses_a_set_deployment_plan(
    monkeypatch: pytest.MonkeyPatch, value: str, replacement: str
) -> None:
    """``DEPLOYMENT_PLAN`` was removed: a pipeline still setting it fails, naming the flag."""
    ctx = CliContext(json_output=True)
    monkeypatch.setenv("DEPLOYMENT_PLAN", value)
    with (
        patch("opentide.core.registry.Opentide.reload") as mock_reload,
        patch("opentide.deployment.make_deploy_plan") as mock_plan,
    ):
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW, dry_run=True)
    mock_reload.assert_not_called()
    mock_plan.assert_not_called()
    assert result["status"] == "failed"
    assert result["_exit_code"] == 2
    assert result["message"] == (
        "DEPLOYMENT_PLAN was removed in 0.17.0: a run now says which status strategy it "
        f"deploys. Use {replacement}. Unset DEPLOYMENT_PLAN. See 'opentide deploy --help'."
    )


def test_run_deploy_ignores_a_blank_deployment_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = CliContext(json_output=True)
    monkeypatch.setenv("DEPLOYMENT_PLAN", "  ")
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={}),
    ):
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
    assert result["status"] == "skipped"


def test_run_deploy_requires_a_strategy() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan") as mock_plan,
    ):
        result = deploy_service.run_deploy(ctx, dry_run=True)
    mock_plan.assert_not_called()
    assert result == {
        "status": "failed",
        "message": deploy_service.STRATEGY_REQUIRED,
        "_exit_code": 2,
    }
    assert deploy_service.STRATEGY_REQUIRED.startswith("Pass --strategy: PREVIEW deploys")


@pytest.mark.parametrize(
    ("value", "hints"),
    [
        (
            "STAGING",
            [
                "--strategy 'STAGING' is not a deployable strategy. Use PREVIEW or RELEASE",
                "STAGING was a deployment plan, removed in 0.17.0: pass PREVIEW",
                (
                    "STAGING is also a configured status name; it maps to PREVIEW, which a PREVIEW "
                    "run deploys"
                ),
            ],
        ),
        (
            "DEVELOPMENT",
            [
                "--strategy 'DEVELOPMENT' is not a deployable strategy",
                "DEVELOPMENT is also a configured status name; it maps to PREVIEW",
            ],
        ),
        ("UNIVERSAL", ["UNIVERSAL is a status strategy that both PREVIEW and RELEASE runs deploy"]),
    ],
)
def test_run_deploy_refuses_a_name_that_is_not_a_run_strategy(value: str, hints: list[str]) -> None:
    """The configured statuses answer a status name with the strategy it maps to."""
    ctx = CliContext(json_output=True)
    with patch("opentide.deployment.make_deploy_plan") as mock_plan:
        result = deploy_service.run_deploy(ctx, strategies=[value], dry_run=True)
    mock_plan.assert_not_called()
    assert result["status"] == "failed"
    assert result["_exit_code"] == 2
    for hint in hints:
        assert hint in str(result["message"])


@pytest.mark.parametrize(
    ("strategies", "all_files", "requested", "keep"),
    [
        pytest.param(["release"], False, None, True, id="RELEASE-diff-keeps"),
        pytest.param(["preview,release"], True, None, False, id="all-drops"),
        pytest.param(["RELEASE"], True, True, True, id="all-keep-deprecated"),
        pytest.param(["PREVIEW"], False, False, False, id="drop-deprecated"),
    ],
)
def test_run_deploy_selects_rules_with_the_run_strategies(
    strategies: list[str], all_files: bool, requested: bool | None, keep: bool
) -> None:
    from opentide.models.deployment_enums import StatusStrategy, parse_strategies

    ctx = CliContext(json_output=True)
    deployer = MagicMock()
    run = parse_strategies(strategies)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.mutation.promotion.PromoteMDR"),
        patch("opentide.deployment.modified_mdr_files"),
        patch(
            "opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}
        ) as mock_plan,
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": deployer}
        result = deploy_service.run_deploy(
            ctx, strategies=strategies, all_files=all_files, keep_deprecated=requested
        )
    assert mock_plan.call_args.args == (run,)
    assert mock_plan.call_args.kwargs["all_files"] is all_files
    assert mock_plan.call_args.kwargs["keep_deprecated"] is keep
    assert mock_plan.call_args.kwargs["wide_scope"] is False
    deployer.deploy.assert_called_once_with(mdr_deployment=["u1"], strategies=run)
    assert result["strategies"] == [s.name for s in run]
    assert all(isinstance(s, StatusStrategy) for s in run)


@pytest.mark.parametrize(
    ("all_files", "requested", "keep"),
    [(False, None, True), (True, None, False), (True, True, True), (False, False, False)],
)
def test_keeps_deprecated(all_files: bool, requested: bool | None, keep: bool) -> None:
    """A RELEASE run retires the changed DISABLEMENT and DELETION rules; ``--all`` does not."""
    assert deploy_service.keeps_deprecated(all_files, requested) is keep


def test_run_deploy_without_a_checkout_names_the_folder_and_all(tmp_path) -> None:
    from opentide.deployment.git_repo import MissingGitCheckout

    ctx = CliContext(json_output=True)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", side_effect=MissingGitCheckout(tmp_path)),
    ):
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert f"no .git was found from {tmp_path}" in str(result["message"])
    assert "pass --all to read every rule file" in str(result["message"])


def test_run_deploy_dry_run_skips_release_promotion(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = CliContext(json_output=True)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )
    monkeypatch.delenv("CI_PIPELINE_SOURCE", raising=False)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.modified_mdr_files") as mock_modified,
        patch("opentide.mutation.promotion.PromoteMDR") as mock_promote,
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.deployment.preview.preview_platform_deployment", return_value=[]),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx, strategies=["RELEASE"], dry_run=True)
    mock_modified.assert_not_called()
    mock_promote.assert_not_called()
    assert result["dry_run"] is True


def test_run_deploy_local_debug_skips_release_promotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = CliContext(json_output=True)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.LocalDebug,
    )
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.modified_mdr_files") as mock_modified,
        patch("opentide.mutation.promotion.PromoteMDR") as mock_promote,
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(ctx, strategies=["RELEASE"], dry_run=False)
    mock_modified.assert_not_called()
    mock_promote.assert_not_called()
    assert result["status"] == "completed"


@pytest.mark.parametrize(
    ("strategies", "all_files", "change_request", "skip", "promoted"),
    [
        pytest.param(["RELEASE"], False, False, False, True, id="RELEASE-push"),
        pytest.param(["PREVIEW", "RELEASE"], False, False, False, True, id="both-push"),
        pytest.param(["PREVIEW"], False, False, False, False, id="PREVIEW-push"),
        pytest.param(["RELEASE"], True, False, False, False, id="RELEASE-all"),
        pytest.param(["RELEASE"], False, True, False, False, id="RELEASE-merge-request"),
        pytest.param(["RELEASE"], False, False, True, False, id="skip-promotion"),
    ],
)
def test_run_deploy_promotes_only_on_a_release_push(
    monkeypatch: pytest.MonkeyPatch,
    strategies: list[str],
    all_files: bool,
    change_request: bool,
    skip: bool,
    promoted: bool,
) -> None:
    """Promotion edits the changed rules before a RELEASE deploy of the default branch."""
    ctx = CliContext(json_output=True)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )
    if change_request:
        monkeypatch.setenv("CI_PIPELINE_SOURCE", "merge_request_event")
    else:
        monkeypatch.delenv("CI_PIPELINE_SOURCE", raising=False)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.modified_mdr_files", return_value=["r.yaml"]) as mock_modified,
        patch("opentide.mutation.promotion.PromoteMDR") as mock_promote,
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        result = deploy_service.run_deploy(
            ctx, strategies=strategies, all_files=all_files, skip_promotion=skip
        )
    assert result["status"] == "completed"
    if promoted:
        mock_modified.assert_called_once_with()
        mock_promote.return_value.promote.assert_called_once_with(["r.yaml"])
    else:
        mock_modified.assert_not_called()
        mock_promote.assert_not_called()


def test_run_deploy_without_tenants_fails_before_loading_engines(tenantless: MagicMock) -> None:
    """#314: the resolver's bare ``raise Exception`` reached the user as a traceback."""
    ctx = CliContext(json_output=True)
    tenantless.return_value = ["splunk"]
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"], "splunk": ["u2"]},
        ),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload") as mock_reload,
        patch("opentide.platforms.enabled.platform_config_path", return_value=SPLUNK_TOML),
    ):
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW)
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
        patch("opentide.core.registry.Opentide.reload"),
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
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW, dry_run=True)
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
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", return_value={"splunk": ["u2"]}),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.deployment.preview.preview_platform_deployment", return_value=[]),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=warned),
        patch("opentide.platforms.enabled.platform_config_path", return_value=SPLUNK_TOML),
    ):
        mock_tide.return_value.mdr_for.return_value = {"splunk": MagicMock()}
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW, dry_run=True)
    assert result["deployed"] == []
    assert result["warnings"] == [
        f"splunk has no tenants configured in {SPLUNK_TOML}, so a real deploy would stop",
        "Some rules reported deployment warnings",
    ]


def test_run_deploy_empty_exception_names_the_exception() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", side_effect=KeyError()),
    ):
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW, dry_run=True)
    assert result["status"] == "failed"
    assert result["message"] == "KeyError while selecting the rules to deploy"


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
def test_run_deploy_reports_selection_warnings_in_every_result(
    plan: dict[str, list[str]] | Exception,
    platform: DetectionPlatform | None,
    engine_error: Exception | None,
    status: str,
    warnings: list[str],
) -> None:
    """#312: a warning raised while selecting rules must reach whichever result follows."""
    ctx = CliContext(json_output=True)
    warned = CiOutcome(exit_code=0, failed=False, warned=True)

    def _plan(*args: object, warnings: list[str], **kwargs: object) -> dict[str, list[str]]:
        warnings.append(SUBFOLDER_WARNING)
        if isinstance(plan, Exception):
            raise plan
        return plan

    with (
        patch("opentide.core.registry.Opentide.reload"),
        patch("opentide.deployment.make_deploy_plan", side_effect=_plan) as mock_plan,
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.index_manager.IndexManager.reload"),
        patch("opentide.cli.exit_codes.deployment_outcome", return_value=warned),
    ):
        mock_tide.return_value.mdr_for.return_value = {"sentinel": MagicMock()}
        if engine_error is not None:
            mock_tide.return_value.mdr_for.side_effect = engine_error
        result = deploy_service.run_deploy(ctx, strategies=PREVIEW, platform=platform)
    mock_plan.assert_called_once()
    assert result["status"] == status
    assert result["warnings"] == warnings
