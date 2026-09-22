"""MCP query tools tell the truth about what they did (#245, #258).

``validate_query`` used to answer ``valid: true`` for any string, and
``run_query`` returned ``rows: 0`` with an empty result set, which reads to an
agent as "the query ran and matched nothing".
"""

from __future__ import annotations

import pytest

from opentide.mcp_server import tools
from opentide.mcp_server.constants import MAX_QUERY_ROWS, QUERY_VALIDATION_PLATFORMS

GARBAGE = 'SecurityEvent | where Account == "unterminated'


def test_query_validation_platform_count() -> None:
    assert len(QUERY_VALIDATION_PLATFORMS) == 5
    assert "crowdstrike" not in QUERY_VALIDATION_PLATFORMS


@pytest.mark.parametrize("platform", sorted(QUERY_VALIDATION_PLATFORMS))
def test_validate_query_reports_offline_mode(platform: str) -> None:
    result = tools.tool_validate_query("DeviceProcessEvents", platform)
    assert result["supported"] is True
    assert result["valid"] is True
    assert result["mode"] == "offline-syntax"
    assert "not executed" in result["message"]


def test_validate_query_rejects_a_broken_query() -> None:
    result = tools.tool_validate_query(GARBAGE, "sentinel")
    assert result["valid"] is False
    assert result["supported"] is True
    (error,) = result["errors"]
    assert error["code"] == "unterminated_string"
    assert error["line"] == 1


@pytest.mark.parametrize("query", ["", "   "])
def test_validate_query_rejects_an_empty_query(query: str) -> None:
    result = tools.tool_validate_query(query, "splunk")
    assert result["valid"] is False
    assert result["errors"][0]["code"] == "empty_query"


@pytest.mark.parametrize("platform", ["crowdstrike", "harfanglab"])
def test_validate_query_never_fakes_an_unsupported_platform(platform: str) -> None:
    result = tools.tool_validate_query("anything at all", platform)
    assert result["supported"] is False
    assert result["valid"] is None
    assert "not supported" in result["message"]


def test_validate_query_truncates_the_preview() -> None:
    result = tools.tool_validate_query("A" * 500, "sentinel")
    assert len(result["query_preview"]) == 200


@pytest.mark.parametrize(("platform", "supported"), [("sentinel", True), ("crowdstrike", False)])
def test_run_query_is_an_explicit_stub(platform: str, supported: bool) -> None:
    result = tools.tool_run_query("index=*", platform, tenant="prod")
    assert result["stub"] is True
    assert result["rows"] is None
    assert result["supported"] is supported
    assert result["tenant"] == "prod"
    # An agent must not be able to read this as an executed, empty result.
    assert "results" not in result
    assert result.get("truncated") is None


def test_run_query_says_it_did_not_run() -> None:
    assert "not implemented" in tools.tool_run_query("index=*", "sentinel")["message"]


def test_run_query_mentions_the_row_cap_the_live_path_would_apply() -> None:
    result = tools.tool_run_query("index=*", "splunk")
    assert str(MAX_QUERY_ROWS) in result["message"]
    assert result["tenant"] is None
