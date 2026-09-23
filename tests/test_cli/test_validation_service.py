"""CLI validation service behaviour."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import ValidateCheck
from opentide.cli.exit_codes import CiOutcome
from opentide.cli.services import validation as validation_service
from opentide.validation.issues import ValidationIssue, ValidationReport

FAILED_OUTCOME = CiOutcome(exit_code=1, failed=True, warned=False)
CLEAN_OUTCOME = CiOutcome(exit_code=0, failed=False, warned=False)


def test_run_validate_cve_delegates_to_session() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(ok=True)
    with (
        patch.object(validation_service, "run_validation", return_value=report) as mock_run,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        result = validation_service.run_validate(ctx, check=ValidateCheck.cve)
    mock_run.assert_called_once()
    assert mock_run.call_args.kwargs["checks"] == frozenset({ValidateCheck.cve})
    assert result["check"] == "cve"
    assert result["status"] == "passed"
    assert result["_exit_code"] == 0


def test_run_validate_cve_failure_sets_exit_code() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="cve", message="unknown CVE")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
    ):
        result = validation_service.run_validate(ctx, check=ValidateCheck.cve)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1


def test_run_validate_cve_skips_run_cve_validation_helper() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(ok=True)
    with (
        patch.object(validation_service, "run_cve_validation") as mock_cve,
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        validation_service.run_validate(ctx, check=ValidateCheck.cve)
    mock_cve.assert_not_called()


def test_run_validate_scope_no_match_report() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="scope_no_match", message="No objects matched")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
    ):
        result = validation_service.run_validate(
            ctx,
            uuids=["00000000-0000-4000-8000-000000000099"],
        )
    assert result["report"]["ok"] is False
    assert result["status"] == "failed"


def test_run_validate_all_default_checks() -> None:
    report = ValidationReport(ok=True, stats={"objects_checked": 1})
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["id-uniqueness"]["status"] == "passed"


def test_run_validate_all_schema_failure_does_not_fail_other_checks() -> None:
    report = ValidationReport(
        ok=False,
        issues=[
            ValidationIssue(
                code="schema_validation",
                message="threat.actors: Input should be a valid dictionary",
                field_path=("threat", "actors"),
            )
        ],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["schema"]["status"] == "failed"
    assert results["id-uniqueness"]["status"] == "passed"
    assert results["uuid-format"]["status"] == "passed"
    assert results["id-uniqueness"]["issues"] == []
    assert results["schema"]["issues"]


def test_run_validate_check_id_uniqueness() -> None:
    report = ValidationReport(ok=True)
    with patch.object(validation_service, "run_validation", return_value=report):
        payload = validation_service.run_validate_check(ValidateCheck.id_uniqueness)
    assert payload["status"] == "passed"


def test_run_id_uniqueness_uuid_and_schema_wrappers() -> None:
    report = ValidationReport(ok=True)
    with patch.object(validation_service, "run_validation", return_value=report) as mock_run:
        validation_service.run_id_uniqueness()
        validation_service.run_uuid_format()
        validation_service.run_schema_validation()
    assert mock_run.call_count == 3


def test_run_validate_default_checks_payload() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(ok=True, stats={"objects_checked": 2})
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        result = validation_service.run_validate(ctx, file="objects/rules/x.yaml")
    assert "checks" in result
    assert "report" in result
    assert result["checks"]["id-uniqueness"]["status"] == "passed"
    assert result["checks"]["schema"]["status"] == "passed"


def _validate_against(workspace: Path, objects_checked: int, **kwargs: object) -> dict[str, object]:
    report = ValidationReport(ok=True, stats={"objects_checked": objects_checked})
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch.object(validation_service, "discover_workspace", return_value=workspace),
    ):
        return validation_service.run_validate(CliContext(json_output=True), **kwargs)


def test_run_validate_reports_the_workspace_it_scanned(tmp_path: Path) -> None:
    result = _validate_against(tmp_path, 3, strict=True)
    assert result["workspace"] == str(tmp_path)
    assert result["message"] == "Validation passed"


@pytest.mark.parametrize("strict", [False, True])
def test_an_empty_catalogue_names_the_workspace_and_still_passes(
    tmp_path: Path, strict: bool
) -> None:
    """#294: from the wrong directory, a bare "Validation passed" had checked nothing."""
    result = _validate_against(tmp_path, 0, strict=strict)
    assert result["message"] == (
        f"Validation passed, but no detection objects were found under {tmp_path}"
    )
    assert result["status"] == "passed"
    assert result["_exit_code"] == 0
    assert "warnings" not in result


def test_a_single_non_object_check_keeps_the_plain_message(tmp_path: Path) -> None:
    """``id-uniqueness`` alone never counts objects, so zero says nothing."""
    result = _validate_against(tmp_path, 0, check=ValidateCheck.id_uniqueness)
    assert result["message"] == "Validation passed"
    assert result["workspace"] == str(tmp_path)


def test_run_validate_default_checks_schema_only_failure() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="schema_validation", message="invalid")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
    ):
        result = validation_service.run_validate(ctx)
    assert result["checks"]["schema"]["status"] == "failed"
    assert result["checks"]["id-uniqueness"]["status"] == "passed"
    assert result["checks"]["uuid-format"]["status"] == "passed"


def test_run_validate_all_uuid_failure_does_not_fail_schema() -> None:
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="invalid_uuid", message="not uuidv4")],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["uuid-format"]["status"] == "failed"
    assert results["schema"]["status"] == "passed"
    assert results["id-uniqueness"]["status"] == "passed"


def test_run_validate_all_duplicate_id_does_not_fail_schema() -> None:
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="duplicate_id", message="dup")],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        results = validation_service.run_validate_all()
    assert results["id-uniqueness"]["status"] == "failed"
    assert results["schema"]["status"] == "passed"


def test_run_validate_check_schema_failure() -> None:
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="schema", message="invalid")],
    )
    with patch.object(validation_service, "run_validation", return_value=report):
        payload = validation_service.run_validate_check(ValidateCheck.schema)
    assert payload["status"] == "failed"


def test_validate_query_platform_skips_when_no_rules(monkeypatch) -> None:
    ctx = CliContext(json_output=True)
    with (
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={},
        ),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
        ),
    ):
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "skipped"


def test_validate_query_platform_runs_validator(monkeypatch) -> None:
    ctx = CliContext(json_output=True)
    validator = MagicMock()
    with (
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"]},
        ),
        patch(
            "opentide.deployment.DeploymentStrategy.load_from_environment",
        ),
        patch(
            "opentide.platforms.plugins.DeployTide",
        ) as mock_tide,
        patch("opentide.core.registry.OpenTide") as mock_ot,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"tide": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    validator.validate.assert_called_once()
    assert result["status"] == "passed"
    assert result["mode"] == "live"


def test_validate_query_platform_is_offline_by_default(monkeypatch) -> None:
    """Issue #239: the default path must not touch the deployment plan at all."""
    ctx = CliContext(json_output=True)

    def _explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline validation must not build a deployment plan")

    with (
        patch("opentide.deployment.make_deploy_plan", side_effect=_explode),
        patch.object(
            validation_service,
            "_offline_query_result",
            return_value={"status": "passed", "mode": "offline-syntax"},
        ) as offline,
    ):
        result = validation_service.validate_query_platform(ctx, "sentinel")
    offline.assert_called_once_with("sentinel")
    assert result["mode"] == "offline-syntax"


def test_validate_query_live_without_the_sdk_names_the_extra() -> None:
    ctx = CliContext(json_output=True)
    validator = MagicMock()
    validator.validate.side_effect = ModuleNotFoundError("No module named 'azure'")
    with (
        patch("opentide.deployment.make_deploy_plan", return_value={"sentinel": ["u1"]}),
        patch("opentide.deployment.DeploymentStrategy.load_from_environment"),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.registry.OpenTide") as mock_ot,
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {"sentinel": {"tide": {"name": "Sentinel"}}}
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert (
        result["advice"]
        == "install opentide[sentinel] (provides azure-identity, azure-monitor-query)"
    )


def test_run_validate_emits_console_issues_when_not_json() -> None:
    ctx = CliContext(json_output=False)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="schema", message="invalid field")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.validation_outcome", return_value=FAILED_OUTCOME),
        patch.object(validation_service.get_stdout_console(), "print") as mock_print,
    ):
        validation_service.run_validate(ctx)
    mock_print.assert_called_once()


def test_validate_query_platform_legacy_validator_signature() -> None:
    ctx = CliContext(json_output=True)
    validator = MagicMock()
    validator.validate.side_effect = [TypeError("legacy"), None]
    with (
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"]},
        ),
        patch("opentide.deployment.DeploymentStrategy.load_from_environment"),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.registry.OpenTide") as mock_ot,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=CLEAN_OUTCOME),
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"platform": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "passed"
    assert validator.validate.call_count == 2


def test_validate_query_platform_warnings_are_not_fatal() -> None:
    ctx = CliContext(json_output=True)
    warned = CiOutcome(exit_code=0, failed=False, warned=True)
    validator = MagicMock()
    with (
        patch(
            "opentide.deployment.make_deploy_plan",
            return_value={"sentinel": ["u1"]},
        ),
        patch("opentide.deployment.DeploymentStrategy.load_from_environment"),
        patch("opentide.platforms.plugins.DeployTide") as mock_tide,
        patch("opentide.core.registry.OpenTide") as mock_ot,
        patch("opentide.cli.exit_codes.validation_outcome", return_value=warned),
    ):
        mock_tide.return_value.query_validation_for.return_value = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"tide": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "passed"
    assert result["_exit_code"] == 0
    assert result["warnings"]


def test_validate_query_empty_exception_does_not_advise_full_plan() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch("opentide.deployment.DeploymentStrategy.load_from_environment"),
        patch("opentide.deployment.make_deploy_plan", side_effect=KeyError()),
    ):
        result = validation_service.validate_query_platform(ctx, "sentinel", live=True)
    assert result["status"] == "failed"
    assert "FULL" not in str(result["message"])
    assert "KeyError" in str(result["message"])
