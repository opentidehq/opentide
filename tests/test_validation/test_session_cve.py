"""Additional tests for validation session CVE wiring."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.cli.exit_codes import report_outcome
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.issues import ValidationIssue
from opentide.validation.session import run_validation


def test_run_validation_includes_cve_check() -> None:
    index = {
        "objects": {"rule": {}, "objective": {}, "threat": {}},
        "metaschemas": {},
        "files": {},
        "vocabs": {},
    }
    cve_issue = ValidationIssue(code="invalid_cve", message="bad cve", object_uuid="u1")
    with (
        patch("opentide.validation.session.Opentide.initialise"),
        patch("opentide.validation.session.PreflightGraph.build", return_value=MagicMock()),
        patch(
            "opentide.validation.cve_check.check_cve_issues",
            return_value=[cve_issue],
        ),
    ):
        report = run_validation(
            checks=frozenset({ValidateCheck.cve}),
            index=index,
            workers=0,
        )
    assert not report.ok
    assert report.issues[0].code == "invalid_cve"


def test_run_validation_reports_an_unreachable_cve_lookup_as_a_warning() -> None:
    """The warning lands in ``warnings``, which ``--strict`` fails on."""
    index = {
        "objects": {"rule": {}, "objective": {}, "threat": {}},
        "metaschemas": {},
        "files": {},
        "vocabs": {},
    }
    warning = ValidationIssue(
        code="cve_lookup_unavailable", severity="warning", message="offline", object_uuid="u1"
    )
    with (
        patch("opentide.validation.session.Opentide.initialise"),
        patch("opentide.validation.session.PreflightGraph.build", return_value=MagicMock()),
        patch("opentide.validation.cve_check.check_cve_issues", return_value=[warning]),
    ):
        report = run_validation(checks=frozenset({ValidateCheck.cve}), index=index, workers=0)
    assert report.ok
    assert report.issues == []
    assert [w.code for w in report.warnings] == ["cve_lookup_unavailable"]
    outcome = report_outcome(report, strict=True)
    assert (outcome.failed, outcome.warned) == (True, True)
    assert report_outcome(report).exit_code == 0
