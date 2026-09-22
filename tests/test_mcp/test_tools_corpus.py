"""MCP tools against tide_corpus instead of a patched ``OpenTide`` (#264)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, CORPUS_TECHNIQUE, CORPUS_THREAT_UUID

from opentide.mcp_server import tools

MISSING_UUID = "00000000-0000-4000-8fff-0000000000ff"


def test_tool_search_returns_summary_list(tide_corpus_repo: Path) -> None:
    payload = tools.tool_search(CORPUS_RULE_UUIDS["sentinel"])
    assert isinstance(payload, list)
    assert [hit["uuid"] for hit in payload] == [CORPUS_RULE_UUIDS["sentinel"]]


def test_tool_coverage_matches_cli_info_coverage(tide_corpus_repo: Path) -> None:
    from opentide.cli.services.info import _technique_coverage

    mcp_rules = set(tools.tool_coverage(technique=CORPUS_TECHNIQUE)["rules"])
    cli_rules = set(_technique_coverage(CORPUS_TECHNIQUE)["rules"])
    assert mcp_rules == cli_rules


def test_tool_get_chaining_resolves_corpus_threat(tide_corpus_repo: Path) -> None:
    payload = tools.tool_get_chaining(CORPUS_THREAT_UUID)
    assert payload["found"] is True


@pytest.mark.parametrize("platform", sorted(CORPUS_RULE_UUIDS))
def test_tool_deployment_status_reads_real_configurations(
    tide_corpus_repo: Path, platform: str
) -> None:
    payload = tools.tool_deployment_status(CORPUS_RULE_UUIDS[platform])
    assert payload["found"] is True
    assert platform in payload["platforms"]


def test_tool_deployment_status_missing_rule(tide_corpus_repo: Path) -> None:
    payload = tools.tool_deployment_status(MISSING_UUID)
    assert payload["found"] is False


def test_tool_validate_rule_on_corpus_rule(tide_corpus_repo: Path) -> None:
    payload = tools.tool_validate_rule(CORPUS_RULE_UUIDS["sentinel"])
    assert payload["errors"] == []
    assert payload["valid"] is True


def test_tool_validate_rule_missing(tide_corpus_repo: Path) -> None:
    payload = tools.tool_validate_rule(MISSING_UUID)
    assert payload["valid"] is False
    assert payload["errors"]


def test_tool_validation_report_full_registry(tide_corpus_repo: Path) -> None:
    payload = tools.tool_validation_report()
    assert "issues" in payload
    assert payload["ok"] is True
