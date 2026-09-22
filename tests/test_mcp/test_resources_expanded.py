"""Resource branches that do not need a registry.

Schema-id resolution and vocabulary serialisation are covered unmocked in
``test_resources_corpus.py``; mocking those indexes hid #254.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from opentide.mcp_server import resources


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


def test_resource_threat_wrong_family() -> None:
    with patch(
        "opentide.mcp_server.resources.get_object",
        return_value={"type": "rule", "body": {}},
    ):
        payload = json.loads(resources.resource_threat("uuid-1"))
    assert "error" in payload


def test_resource_objective_wrong_family() -> None:
    with patch(
        "opentide.mcp_server.resources.get_object",
        return_value={"type": "rule", "body": {}},
    ):
        payload = json.loads(resources.resource_objective("uuid-1"))
    assert "error" in payload
