"""CI-aware CLI exit code helpers."""

from __future__ import annotations

import os

import pytest

from opentide.cli import exit_codes
from opentide.validation.issues import ValidationIssue, ValidationReport


def test_exit_on_deployment_errors_raises_when_flag_set() -> None:
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    try:
        with pytest.raises(SystemExit) as exc:
            exit_codes.exit_on_deployment_errors()
        assert exc.value.code == 1
    finally:
        os.environ.pop("DEPLOYMENT_ERROR_RAISED", None)


def test_validation_outcome_strict_fails_on_warning() -> None:
    assert exit_codes.validation_outcome(failed=False, warned=True, strict=True).exit_code == 1
    assert exit_codes.validation_outcome(failed=False, warned=True, strict=False).exit_code == 0


def test_validation_outcome_never_uses_exit_19() -> None:
    outcome = exit_codes.validation_outcome(failed=False, warned=True)
    assert outcome.failed is False
    assert outcome.warned is True
    assert outcome.exit_code == 0
    assert outcome.exit_code != 19


def test_validation_outcome_ignores_the_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retired ``VALIDATION_*_RAISED`` flags grade nothing: the run's findings do (#673)."""
    monkeypatch.setenv("VALIDATION_ERROR_RAISED", "1")
    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    outcome = exit_codes.validation_outcome(failed=False, warned=False, strict=True)
    assert outcome == exit_codes.CiOutcome(exit_code=0, failed=False, warned=False)


def _issue(code: str, severity: str = "warning") -> ValidationIssue:
    return ValidationIssue(code=code, severity=severity, message=code, field_path=())


def test_report_outcome_grades_the_report() -> None:
    clean = ValidationReport(ok=True)
    warned = ValidationReport(ok=True, warnings=[_issue("deprecated_field")])
    failed = ValidationReport(ok=False, issues=[_issue("missing_uuid", "error")])
    assert exit_codes.report_outcome(clean, strict=True).exit_code == 0
    assert exit_codes.report_outcome(warned).exit_code == 0
    assert exit_codes.report_outcome(warned, strict=True).exit_code == 1
    assert exit_codes.report_outcome(failed).failed is True


def test_report_outcome_never_fails_strict_on_a_disabled_platform() -> None:
    from opentide.validation.disabled_platforms import PLATFORM_NOT_ENABLED

    report = ValidationReport(ok=True, warnings=[_issue(PLATFORM_NOT_ENABLED)])
    assert exit_codes.report_outcome(report, strict=True) == exit_codes.CiOutcome(
        exit_code=0, failed=False, warned=False
    )


def test_deployment_outcome_error_marks_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_ERROR_RAISED", "1")
    monkeypatch.delenv("DEPLOYMENT_WARNING_RAISED", raising=False)
    outcome = exit_codes.deployment_outcome()
    assert outcome.failed is True
    assert outcome.exit_code == 1
    assert exit_codes.deployment_exit_code() == 1


def test_deployment_warnings_do_not_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED", raising=False)
    monkeypatch.setenv("DEPLOYMENT_WARNING_RAISED", "1")
    outcome = exit_codes.deployment_outcome()
    assert outcome.failed is False
    assert outcome.warned is True
    assert outcome.exit_code == 0
