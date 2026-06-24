"""Tests for MCP catalog object lookup branches."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.mcp_server.catalog import get_object


def test_get_object_finds_threat() -> None:
    mock_models = MagicMock()
    mock_models.rules = {}
    mock_models.threats = {"t1": {"name": "Threat"}}
    mock_models.objectives = {}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        found = get_object("t1")
    assert found is not None
    assert found["type"] == "threat"


def test_get_object_finds_objective() -> None:
    mock_models = MagicMock()
    mock_models.rules = {}
    mock_models.threats = {}
    mock_models.objectives = {"o1": {"name": "Objective"}}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        found = get_object("o1")
    assert found["type"] == "objective"
