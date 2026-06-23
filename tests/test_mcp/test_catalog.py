"""MCP catalog search and analysis."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.mcp_server.catalog import (
    coverage_analysis,
    get_chaining_graph,
    get_object,
    object_summary,
    search_catalog,
)


def test_object_summary_uses_name_or_title() -> None:
    summary = object_summary("uuid-1", "rule", {"name": "My Rule", "status": "STAGING"})
    assert summary["title"] == "My Rule"
    assert summary["type"] == "rule"
    assert summary["uuid"] == "uuid-1"


def test_get_object_returns_none_when_missing(monkeypatch) -> None:
    mock_models = MagicMock()
    mock_models.rule = {}
    mock_models.threat = {}
    mock_models.objective = {}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        assert get_object("missing-uuid") is None


def test_search_catalog_by_uuid(monkeypatch) -> None:
    rule_uuid = "00000000-0000-4000-8000-000000000099"
    mock_models = MagicMock()
    mock_models.rule = {rule_uuid: {"name": "Found Rule", "status": "STAGING"}}
    mock_models.threat = {}
    mock_models.objective = {}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        result = search_catalog(rule_uuid)
    assert isinstance(result, dict)
    assert result["uuid"] == rule_uuid


def test_search_catalog_keyword_filter(monkeypatch) -> None:
    mock_models = MagicMock()
    mock_models.rule = {
        "uuid-a": {"name": "Alpha Rule", "description": "detects alpha"},
        "uuid-b": {"name": "Beta Rule", "description": "detects beta"},
    }
    mock_models.threat = {}
    mock_models.objective = {}
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        results = search_catalog("alpha")
    assert len(results) == 1
    assert results[0]["title"] == "Alpha Rule"


def test_get_chaining_graph_not_found(monkeypatch) -> None:
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models.chaining = {}
        mock_ot.initialise = MagicMock()
        with patch("opentide.mcp_server.catalog.get_object", return_value=None):
            graph = get_chaining_graph("missing")
    assert graph["found"] is False


def test_coverage_analysis_by_technique(monkeypatch) -> None:
    mock_models = MagicMock()
    mock_models.rule = {
        "rule-1": {"tags": {"techniques": ["T1059"]}},
    }
    with patch("opentide.mcp_server.catalog.OpenTide") as mock_ot:
        mock_ot.Models = mock_models
        mock_ot.initialise = MagicMock()
        result = coverage_analysis(technique="T1059")
    assert result["covered"] is True
    assert "rule-1" in result["rules"]
