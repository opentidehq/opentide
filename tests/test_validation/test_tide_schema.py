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


def test_run_prints_stats_when_validation_passes() -> None:
    report = MagicMock()
    report.issues = []
    mock_index = {"objects": {"rule": {"a": {}, "b": {}}}}
    mock_opentide = MagicMock()
    mock_opentide.Index = mock_index

    with (
        patch("opentide.validation.tide_schema.OpenTide", mock_opentide),
        patch("opentide.validation.tide_schema.run_validation", return_value=report),
        patch("opentide.validation.tide_schema.emit_section"),
        patch("builtins.print") as mock_print,
    ):
        tide_schema.run()

    mock_opentide.initialise.assert_called_once()

    printed = " ".join(str(call.args[0]) for call in mock_print.call_args_list)
    assert "RULE" in printed
    assert "2" in printed
