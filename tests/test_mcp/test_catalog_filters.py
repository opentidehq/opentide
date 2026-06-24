"""Additional MCP catalog filter coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.mcp_server.catalog import coverage_analysis, get_chaining_graph, search_catalog


def test_search_catalog_technique_filter() -> None:
    mock_models = MagicMock()
    mock_models.rules = {
        "r1": {"name": "Rule", "tags": {"techniques": ["T1059"]}},
        "r2": {"name": "Other", "tags": {"techniques": ["T1003"]}},
    }
    mock_models.threats = {}
    mock_models.objectives = {}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        results = search_catalog("rule", technique="T1059")
    assert len(results) == 1


def test_search_catalog_actor_filter() -> None:
    mock_models = MagicMock()
    mock_models.rules = {}
    mock_models.threats = {
        "t1": {"name": "Threat", "tags": {"actors": ["APT29"]}},
    }
    mock_models.objectives = {}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        results = search_catalog("threat", actor="apt29")
    assert len(results) == 1


def test_search_catalog_platform_filter() -> None:
    mock_models = MagicMock()
    mock_models.rules = {
        "r1": {"name": "Sentinel Rule", "configurations": {"sentinel": {}}},
    }
    mock_models.threats = {}
    mock_models.objectives = {}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        results = search_catalog("sentinel", platform="sentinel")
    assert len(results) == 1


def test_get_chaining_graph_found() -> None:
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models.chaining = {"u1": {"parents": []}}
        mock_ot.initialise = MagicMock()
        with patch(
            "opentide.mcp_server.catalog.get_object",
            return_value={"type": "threat", "uuid": "u1", "body": {}},
        ):
            graph = get_chaining_graph("u1")
    assert graph["found"] is True


def test_coverage_analysis_matrix() -> None:
    mock_models = MagicMock()
    mock_models.rules = {"r1": {"tags": {"techniques": ["T1059", "T1003"]}}}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        result = coverage_analysis()
    assert result["technique_count"] == 2
    assert "T1059" in result["matrix"]
