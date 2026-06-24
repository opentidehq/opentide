"""CLI validation service behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.cli.context import CliContext
from opentide.cli.enums import ValidateCheck
from opentide.cli.services import validation as validation_service
from opentide.validation.issues import ValidationIssue, ValidationReport


def test_run_validate_cve_delegates_to_cve_runner() -> None:
    ctx = CliContext(json_output=True)
    with patch.object(validation_service, "run_cve_validation") as mock_cve:
        result = validation_service.run_validate(ctx, check=ValidateCheck.cve)
    mock_cve.assert_called_once()
    assert result["check"] == "cve"


def test_run_validate_cve_skips_run_validation() -> None:
    ctx = CliContext(json_output=True)
    with (
        patch.object(validation_service, "run_cve_validation"),
        patch.object(validation_service, "run_validation") as mock_run,
    ):
        validation_service.run_validate(ctx, check=ValidateCheck.cve)
    mock_run.assert_not_called()


def test_run_validate_scope_no_match_report() -> None:
    ctx = CliContext(json_output=True)
    report = ValidationReport(
        ok=False,
        issues=[ValidationIssue(code="scope_no_match", message="No objects matched")],
    )
    with (
        patch.object(validation_service, "run_validation", return_value=report),
        patch("opentide.cli.exit_codes.exit_on_validation_errors"),
        patch("opentide.cli.exit_codes.exit_on_validation_warnings"),
    ):
        result = validation_service.run_validate(
            ctx,
            uuids=["00000000-0000-4000-8000-000000000099"],
        )
    assert result["report"]["ok"] is False


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
        patch("opentide.cli.exit_codes.exit_on_validation_errors"),
        patch("opentide.cli.exit_codes.exit_on_validation_warnings"),
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
        patch("opentide.cli.exit_codes.exit_on_validation_errors"),
        patch("opentide.cli.exit_codes.exit_on_validation_warnings"),
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
        patch("opentide.cli.exit_codes.exit_on_validation_errors"),
        patch("opentide.cli.exit_codes.exit_on_validation_warnings"),
        patch.object(validation_service.logger, "error") as mock_log,
    ):
        validation_service.run_validate(ctx)
    mock_log.assert_called()


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
        patch("opentide.cli.exit_codes.exit_on_validation_errors"),
        patch("opentide.cli.exit_codes.exit_on_validation_warnings"),
    ):
        mock_tide.return_value.query_validation = {"sentinel": validator}
        mock_ot.Configurations.Systems.Index = {
            "sentinel": {"platform": {"name": "Sentinel"}},
        }
        result = validation_service.validate_query_platform(ctx, "sentinel")
    assert result["status"] == "passed"
    assert validator.validate.call_count == 2
