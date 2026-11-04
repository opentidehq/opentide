"""Tests for tide_schema validation entrypoint."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.validation import tide_schema


def test_format_stats_table_renders_header_and_rows() -> None:
    table = tide_schema._format_stats_table([["Category", "Count"], ["RULE", 3]])
    assert "Category" in table
    assert "RULE" in table
    assert "3" in table
    assert "-+-" in table


def test_format_stats_table_empty_returns_blank() -> None:
    assert tide_schema._format_stats_table([]) == ""


def test_run_prints_stats_when_validation_passes() -> None:
    report = MagicMock()
    report.issues = []
    mock_index = {"objects": {"rule": {"a": {}, "b": {}}}}
    mock_opentide = MagicMock()
    mock_opentide.Index = mock_index

    with (
        patch("opentide.validation.tide_schema.Opentide", mock_opentide),
        patch("opentide.validation.tide_schema.run_validation", return_value=report),
        patch("opentide.validation.tide_schema.report_stage"),
        # Logging configuration is process-global: an earlier `--json` CLI test
        # in the same worker would otherwise suppress the human-readable table.
        patch("opentide.validation.tide_schema.is_json_output", return_value=False),
        patch.object(tide_schema.get_stdout_console(), "print") as mock_print,
    ):
        assert tide_schema.run() is report

    mock_opentide.initialise.assert_called_once()

    printed = " ".join(str(call.args[0]) for call in mock_print.call_args_list)
    assert "RULE" in printed
    assert "2" in printed


def test_run_returns_the_failed_report_when_issues_present() -> None:
    report = MagicMock()
    issue = MagicMock()
    issue.object_uuid = "uuid-1"
    issue.to_legacy_string.return_value = "schema error"
    report.issues = [issue]
    mock_index = {"objects": {"rule": {"a": {}}}}
    mock_opentide = MagicMock()
    mock_opentide.Index = mock_index

    with (
        patch("opentide.validation.tide_schema.Opentide", mock_opentide),
        patch("opentide.validation.tide_schema.run_validation", return_value=report),
        patch("opentide.validation.tide_schema.report_stage"),
        patch("opentide.validation.tide_schema.format_issues_for_console", return_value="issues"),
        # Pinned, as above: an earlier `--json` test in the worker skipped the print.
        patch("opentide.validation.tide_schema.is_json_output", return_value=False),
        patch.object(tide_schema.get_stdout_console(), "print") as mock_print,
    ):
        assert tide_schema.run() is report
    mock_print.assert_called_once_with("issues", markup=False)
