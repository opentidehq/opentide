"""MCP catalog filter semantics against tide_corpus."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, CORPUS_TECHNIQUE, CORPUS_THREAT_UUID

from opentide.mcp_server.catalog import search_catalog


def test_platform_filter_matches_configuration_keys(tide_corpus_repo: Path) -> None:
    """#253: ``sentinel`` used to substring-match the ``sentinel_one`` key."""
    hits = {hit["uuid"] for hit in search_catalog("Rule", platform="sentinel")}
    assert CORPUS_RULE_UUIDS["sentinel"] in hits
    assert CORPUS_RULE_UUIDS["sentinel_one"] not in hits


def test_sentinel_one_filter_is_reachable(tide_corpus_repo: Path) -> None:
    hits = {hit["uuid"] for hit in search_catalog("Rule", platform="sentinel_one")}
    assert hits == {CORPUS_RULE_UUIDS["sentinel_one"]}


@pytest.mark.parametrize("platform", sorted(CORPUS_RULE_UUIDS))
def test_every_corpus_platform_filters_to_its_own_rule(
    tide_corpus_repo: Path, platform: str
) -> None:
    hits = {hit["uuid"] for hit in search_catalog("", platform=platform)}
    assert CORPUS_RULE_UUIDS[platform] in hits


def test_unknown_platform_returns_nothing(tide_corpus_repo: Path) -> None:
    assert search_catalog("Rule", platform="nonexistent") == []


def test_technique_filter_on_top_level_field(tide_corpus_repo: Path) -> None:
    hits = {hit["uuid"] for hit in search_catalog("Rule", technique=CORPUS_TECHNIQUE)}
    assert hits >= set(CORPUS_RULE_UUIDS.values())


def test_technique_filter_reads_threat_attack_section(tide_corpus_repo: Path) -> None:
    hits = {hit["uuid"] for hit in search_catalog("Simulated", technique=CORPUS_TECHNIQUE)}
    assert CORPUS_THREAT_UUID in hits


def test_unknown_technique_returns_nothing(tide_corpus_repo: Path) -> None:
    assert search_catalog("Rule", technique="T9999") == []


def test_filters_combine(tide_corpus_repo: Path) -> None:
    hits = search_catalog("Rule", platform="splunk", technique=CORPUS_TECHNIQUE, status="STAGING")
    assert [hit["uuid"] for hit in hits] == [CORPUS_RULE_UUIDS["splunk"]]
