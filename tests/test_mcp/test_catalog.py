"""MCP catalog search and analysis against the real tide_corpus registry.

These tests deliberately avoid patching ``OpenTide``: the mocked variants used
to assert the broken contracts from #252–#253 (dict-shaped UUID search,
``tags``-only technique lookup, substring platform matching).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.corpus_support import (
    CORPUS_ACTOR,
    CORPUS_OBJECTIVE_UUID,
    CORPUS_RULE_UUIDS,
    CORPUS_TECHNIQUE,
    CORPUS_THREAT_UUID,
)

from opentide.mcp_server.catalog import (
    coverage_analysis,
    get_chaining_graph,
    get_object,
    object_summary,
    search_catalog,
)

MISSING_UUID = "00000000-0000-4000-8fff-0000000000ff"
SUMMARY_KEYS = {"uuid", "type", "title", "status"}


def test_object_summary_uses_name_or_title() -> None:
    summary = object_summary("uuid-1", "rule", {"name": "My Rule", "status": "STAGING"})
    assert summary["title"] == "My Rule"
    assert summary["type"] == "rule"
    assert summary["uuid"] == "uuid-1"


def test_get_object_resolves_every_family(tide_corpus_repo: Path) -> None:
    rule = get_object(CORPUS_RULE_UUIDS["sentinel"])
    threat = get_object(CORPUS_THREAT_UUID)
    objective = get_object(CORPUS_OBJECTIVE_UUID)
    assert rule is not None and rule["type"] == "rule"
    assert threat is not None and threat["type"] == "threat"
    assert objective is not None and objective["type"] == "objective"


def test_get_object_returns_none_when_missing(tide_corpus_repo: Path) -> None:
    assert get_object(MISSING_UUID) is None


def test_search_by_uuid_returns_a_summary_list(tide_corpus_repo: Path) -> None:
    """#253: UUID search used to return a single dict with a full ``body``."""
    result = search_catalog(CORPUS_RULE_UUIDS["sentinel"])
    assert isinstance(result, list)
    assert len(result) == 1
    assert set(result[0]) == SUMMARY_KEYS
    assert result[0]["uuid"] == CORPUS_RULE_UUIDS["sentinel"]
    assert "body" not in result[0]


def test_search_by_unknown_uuid_returns_empty_list(tide_corpus_repo: Path) -> None:
    assert search_catalog(MISSING_UUID) == []


def test_search_keyword_and_uuid_share_one_shape(tide_corpus_repo: Path) -> None:
    keyword = search_catalog("Sentinel KQL")
    by_uuid = search_catalog(CORPUS_RULE_UUIDS["sentinel"])
    assert [set(hit) for hit in keyword] == [SUMMARY_KEYS for _ in keyword]
    assert {hit["uuid"] for hit in keyword} >= {CORPUS_RULE_UUIDS["sentinel"]}
    assert set(by_uuid[0]) == set(keyword[0])


def test_search_object_type_filter(tide_corpus_repo: Path) -> None:
    results = search_catalog("simulated", object_type="threat")
    assert results
    assert {hit["type"] for hit in results} == {"threat"}


def test_search_status_filter(tide_corpus_repo: Path) -> None:
    results = search_catalog("rule", status="STAGING")
    assert results
    assert {hit["status"] for hit in results} == {"STAGING"}


def test_get_chaining_graph_found(tide_corpus_repo: Path) -> None:
    graph = get_chaining_graph(CORPUS_THREAT_UUID)
    assert graph["found"] is True
    assert graph["type"] == "threat"


def test_get_chaining_graph_not_found(tide_corpus_repo: Path) -> None:
    assert get_chaining_graph(MISSING_UUID)["found"] is False


def test_coverage_reads_top_level_techniques(tide_corpus_repo: Path) -> None:
    """#252: corpus rules store ``techniques`` at top level, not under ``tags``."""
    result = coverage_analysis(technique=CORPUS_TECHNIQUE)
    assert result["covered"] is True
    assert set(result["rules"]) >= set(CORPUS_RULE_UUIDS.values())


def test_coverage_matrix_lists_corpus_techniques(tide_corpus_repo: Path) -> None:
    result = coverage_analysis()
    assert CORPUS_TECHNIQUE in result["matrix"]
    assert result["technique_count"] == len(result["matrix"])
    assert result["tactic_filter"] is None


def test_coverage_unknown_technique_is_not_covered(tide_corpus_repo: Path) -> None:
    result = coverage_analysis(technique="T9999")
    assert result["covered"] is False
    assert result["rules"] == []
    assert result["matched_techniques"] == []


def test_coverage_for_a_parent_includes_sub_technique_rules(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rules tagged ``T1059.001`` answer "what do we detect for T1059?"."""
    from opentide.core.registry import OpenTide
    from opentide.mcp_server.catalog import ensure_initialised

    ensure_initialised()
    sub_uuid = "00000000-0000-4000-8003-0000000000aa"
    monkeypatch.setitem(
        OpenTide.Models.rules, sub_uuid, {"name": "PowerShell", "techniques": ["T1059.001"]}
    )

    parent = coverage_analysis(technique="T1059")
    assert sub_uuid in parent["rules"]
    assert set(parent["matched_techniques"]) >= {"T1059", "T1059.001"}

    child = coverage_analysis(technique="T1059.001")
    assert child["rules"] == [sub_uuid], "a sub-technique query must not widen to its parent"


def test_search_actor_reads_threat_actors(tide_corpus_repo: Path) -> None:
    """#252: the actor filter only ever read ``tags.actors``."""
    namespaced = search_catalog("Simulated", actor=CORPUS_ACTOR)
    bare = search_catalog("Simulated", actor="G0006")
    assert [hit["uuid"] for hit in namespaced] == [CORPUS_THREAT_UUID]
    assert [hit["uuid"] for hit in bare] == [CORPUS_THREAT_UUID]
