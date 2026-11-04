"""MCP validation report tool tests."""

from __future__ import annotations

from unittest.mock import patch

from opentide.mcp_server.tools import tool_validation_report
from opentide.validation.issues import ValidationReport


def test_tool_validation_report_full_scope() -> None:
    report = ValidationReport(ok=True, stats={"objects_checked": 0})
    with (
        patch("opentide.mcp_server.tools.Opentide.reload"),
        patch("opentide.validation.session.run_validation", return_value=report),
    ):
        payload = tool_validation_report()
    assert payload["ok"] is True


def test_tool_validation_report_narrow_scope() -> None:
    report = ValidationReport(ok=True)
    with (
        patch("opentide.mcp_server.tools.Opentide.reload"),
        patch("opentide.validation.session.run_validation", return_value=report) as mock_run,
    ):
        tool_validation_report(file="rule.yaml", uuid="u1", object_type="rule")
    mock_run.assert_called_once()


def test_tool_validation_report_checks_queries_as_validate_does() -> None:
    from opentide.cli.enums import ValidateCheck
    from opentide.validation.issues import ValidationIssue

    issue = ValidationIssue(code="kql_parse_error", severity="error", message="KQL syntax error")
    report = ValidationReport(ok=False, issues=[issue])
    with (
        patch("opentide.mcp_server.tools.Opentide.reload"),
        patch("opentide.validation.session.run_validation", return_value=report) as mock_run,
    ):
        default = tool_validation_report()
        assert ValidateCheck.queries in mock_run.call_args.kwargs["checks"]
        assert mock_run.call_args.kwargs["queries_as_warnings"] is False
        assert default["next_actions"][-1]["command"] == "opentide --json validate"

        warned = tool_validation_report(uuid="u1", queries="warn")
        assert mock_run.call_args.kwargs["queries_as_warnings"] is True
        again = warned["next_actions"][-1]
        assert again["command"] == "opentide --json validate --uuid u1 --queries warn"
        assert again["arguments"] == {"uuid": "u1", "queries": "warn"}

        tool_validation_report(queries="off")
        assert ValidateCheck.queries not in mock_run.call_args.kwargs["checks"]


def test_tool_validation_report_refuses_an_unknown_queries_mode() -> None:
    with patch("opentide.validation.session.run_validation") as mock_run:
        payload = tool_validation_report(queries="loud")
    mock_run.assert_not_called()
    assert payload["ok"] is False
    assert payload["error"] == "queries must be one of error, warn, off, got 'loud'"
