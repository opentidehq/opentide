"""Tests for thin legacy validation script entrypoints."""

from __future__ import annotations

from unittest.mock import patch

from opentide.validation import cve, id_uniqueness, uuid_v4
from opentide.validation.issues import ValidationIssue, ValidationReport


def test_id_uniqueness_run_delegates_to_session() -> None:
    issue = ValidationIssue(code="duplicate_id", message="dup")
    report = ValidationReport(ok=False, issues=[issue])
    with (
        patch.object(id_uniqueness, "OpenTide") as mock_tide,
        patch("opentide.validation.id_uniqueness.run_validation", return_value=report) as mock_run,
        patch.object(id_uniqueness, "emit_section"),
    ):
        id_uniqueness.run()
    mock_tide.initialise.assert_called_once()
    mock_run.assert_called_once()


def test_uuid_v4_run_delegates_to_session() -> None:
    report = ValidationReport(ok=True)
    with (
        patch.object(uuid_v4, "OpenTide") as mock_tide,
        patch("opentide.validation.uuid_v4.run_validation", return_value=report) as mock_run,
        patch.object(uuid_v4, "emit_section"),
    ):
        uuid_v4.run()
    mock_tide.initialise.assert_called_once()
    mock_run.assert_called_once()


def test_cve_run_delegates_to_session() -> None:
    report = ValidationReport(ok=True)
    with (
        patch.object(cve, "OpenTide") as mock_tide,
        patch("opentide.validation.cve.run_validation", return_value=report) as mock_run,
        patch.object(cve, "emit_section"),
    ):
        cve.run()
    mock_tide.initialise.assert_called_once()
    mock_run.assert_called_once()
