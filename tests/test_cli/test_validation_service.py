"""CLI validation service behaviour."""

from __future__ import annotations

from unittest.mock import patch

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
