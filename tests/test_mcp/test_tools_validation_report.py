"""MCP validation report tool tests."""

from __future__ import annotations

from unittest.mock import patch

from opentide.mcp_server.tools import tool_validation_report
from opentide.validation.issues import ValidationReport


def test_tool_validation_report_full_scope() -> None:
    report = ValidationReport(ok=True, stats={"objects_checked": 0})
    with (
        patch("opentide.mcp_server.tools.ensure_initialised"),
        patch("opentide.validation.session.run_validation", return_value=report),
    ):
        payload = tool_validation_report()
    assert payload["ok"] is True


def test_tool_validation_report_narrow_scope() -> None:
    report = ValidationReport(ok=True)
    with (
        patch("opentide.mcp_server.tools.ensure_initialised"),
        patch("opentide.validation.session.run_validation", return_value=report) as mock_run,
    ):
        tool_validation_report(file="rule.yaml", uuid="u1", object_type="rule")
    mock_run.assert_called_once()
