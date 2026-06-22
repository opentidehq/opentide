"""MCP server unit tests."""

from __future__ import annotations

from opentide.mcp_server.constants import QUERY_VALIDATION_PLATFORMS
from opentide.mcp_server.tools import tool_validate_query


def test_validate_query_crowdstrike_unsupported() -> None:
    result = tool_validate_query("DeviceProcessEvents | take 10", "crowdstrike")
    assert result["supported"] is False
    assert "not supported" in result["message"]


def test_validate_query_sentinel_supported() -> None:
    result = tool_validate_query("DeviceProcessEvents | take 10", "sentinel")
    assert result["supported"] is True


def test_query_validation_platform_count() -> None:
    assert len(QUERY_VALIDATION_PLATFORMS) == 5
