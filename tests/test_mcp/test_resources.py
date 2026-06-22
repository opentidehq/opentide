"""MCP resource tests."""

from __future__ import annotations

import json

from opentide.mcp_server.resources import resource_platforms


def test_resource_platforms_exposes_capabilities() -> None:
    payload = json.loads(resource_platforms())
    crowdstrike = next(p for p in payload if p["name"] == "crowdstrike")
    assert crowdstrike["can_validate"] is False
