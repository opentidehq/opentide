"""CLI validation service behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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
        result = validation_service.validate_query_platform(ctx, "sentinel")
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
        mock_tide.return_value.query_validation = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"tide": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel")
    validator.validate.assert_called_once()
    assert result["status"] == "passed"


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
        mock_tide.return_value.query_validation = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"platform": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel")
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
        mock_tide.return_value.query_validation = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"tide": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel")
    assert result["status"] == "passed"
    assert result["_exit_code"] == 0
    assert result["warnings"]
