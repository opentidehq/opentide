"""Expanded MCP tool coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.mcp_server import tools
from opentide.validation.issues import ValidationReport


def test_tool_validate_query_unsupported_platform() -> None:
    result = tools.tool_validate_query("index=*", "crowdstrike")
    assert result["supported"] is False


def test_tool_validate_query_supported_platform() -> None:
    result = tools.tool_validate_query("DeviceProcessEvents", "sentinel")
    assert result["supported"] is True
    assert result["valid"] is True


def test_tool_run_query_returns_stub() -> None:
    result = tools.tool_run_query("index=*", "splunk", tenant="prod")
    assert result["rows"] == 0
    assert result["tenant"] == "prod"


def test_tool_validate_rule_not_found() -> None:
    with (
        patch("opentide.mcp_server.tools.ensure_initialised"),
        patch("opentide.mcp_server.tools.OpenTide") as mock_tide,
    ):
        mock_tide.Rules.get.return_value = None
        result = tools.tool_validate_rule("missing-uuid")
    assert result["valid"] is False


def test_tool_validate_rule_found() -> None:
    report = ValidationReport(ok=True)
    with (
        patch("opentide.mcp_server.tools.ensure_initialised"),
        patch("opentide.mcp_server.tools.OpenTide") as mock_tide,
        patch("opentide.validation.session.run_validation", return_value=report),
    ):
        mock_tide.Rules.get.return_value = MagicMock()
        result = tools.tool_validate_rule("00000000-0000-4000-8000-000000000001")
    assert result["valid"] is True


def test_tool_deployment_status_not_found() -> None:
    with (
        patch("opentide.mcp_server.tools.ensure_initialised"),
        patch("opentide.mcp_server.tools.OpenTide") as mock_tide,
    ):
        mock_tide.Models.rules.get.return_value = None
        result = tools.tool_deployment_status("missing")
    assert result["found"] is False


def test_tool_deployment_status_found() -> None:
    with (
        patch("opentide.mcp_server.tools.ensure_initialised"),
        patch("opentide.mcp_server.tools.OpenTide") as mock_tide,
    ):
        mock_tide.Models.rules.get.return_value = {
            "configurations": {"sentinel": {"external_id": "123", "tenants": ["t1"]}}
        }
        result = tools.tool_deployment_status("uuid-1")
    assert result["found"] is True
    assert "sentinel" in result["platforms"]
