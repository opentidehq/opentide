"""Expanded MCP resource coverage."""

from __future__ import annotations

import json
from unittest.mock import patch

from opentide.mcp_server import resources


def test_resource_index() -> None:
    with (
        patch("opentide.mcp_server.resources.ensure_initialised"),
        patch("opentide.mcp_server.resources.OpenTide") as mock_tide,
    ):
        mock_tide.Index = {"objects": {}}
        payload = json.loads(resources.resource_index())
    assert "objects" in payload


def test_resource_rule_found() -> None:
    with patch(
        "opentide.mcp_server.resources.get_object",
        return_value={"type": "rule", "body": {"name": "R1"}},
    ):
        payload = json.loads(resources.resource_rule("uuid-1"))
    assert payload["name"] == "R1"


def test_resource_rule_missing() -> None:
    with patch("opentide.mcp_server.resources.get_object", return_value=None):
        payload = json.loads(resources.resource_rule("missing"))
    assert "error" in payload


def test_resource_schema_and_template() -> None:
    with (
        patch("opentide.mcp_server.resources.ensure_initialised"),
        patch("opentide.mcp_server.resources.OpenTide") as mock_tide,
    ):
        mock_tide.JsonSchemas.Index = {"rule": {"type": "object"}}
        mock_tide.Templates.Index = {"rule": {"template": True}}
        schema = json.loads(resources.resource_schema("rule"))
        template = json.loads(resources.resource_template("rule"))
    assert schema["type"] == "object"
    assert template["template"] is True


def test_resource_vocabulary_lookup() -> None:
    with (
        patch("opentide.mcp_server.resources.ensure_initialised"),
        patch("opentide.mcp_server.resources.OpenTide") as mock_tide,
    ):
        mock_tide.Vocabularies.Index = {"severity": {"entries": []}}
        payload = json.loads(resources.resource_vocabulary("severity"))
    assert "entries" in payload


def test_resource_lists() -> None:
    with (
        patch("opentide.mcp_server.resources.ensure_initialised"),
        patch("opentide.mcp_server.resources.OpenTide") as mock_tide,
    ):
        mock_tide.Models.rules = {"u1": {}}
        mock_tide.Models.threats = {}
        mock_tide.Models.objectives = {}
        assert json.loads(resources.resource_rules()) == {"u1": {}}
        assert json.loads(resources.resource_threats()) == {}
        assert json.loads(resources.resource_objectives()) == {}
