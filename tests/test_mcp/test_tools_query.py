"""MCP query tools tell the truth about what they did (#245, #258).

``validate_query`` used to answer ``valid: true`` for any string (it now runs
the analysis engine on it, #332), and
``run_query`` returned ``rows: 0`` with an empty result set, which reads to an
agent as "the query ran and matched nothing".
"""

from __future__ import annotations

import pytest

from opentide.mcp_server import tools
from opentide.mcp_server.constants import MAX_QUERY_ROWS, QUERY_VALIDATION_PLATFORMS

GARBAGE = 'SecurityEvent | where Account == "unterminated'


def test_query_validation_platform_count() -> None:
    assert len(QUERY_VALIDATION_PLATFORMS) == 6
    assert "crowdstrike" not in QUERY_VALIDATION_PLATFORMS


#: A query each offline platform's engine accepts.
VALID_QUERIES = {
    "sentinel": "SecurityEvent | where EventID == 4688",
    "defender_for_endpoint": "DeviceProcessEvents | where FileName == 'x.exe'",
    "splunk": "index=main sourcetype=WinEventLog EventCode=4688",
    "elastic": 'process.name : "cmd.exe"',
    "carbon_black_cloud": "process_name:cmd.exe",
}


@pytest.mark.parametrize("platform", sorted(VALID_QUERIES))
def test_validate_query_checks_the_query_offline(platform: str) -> None:
    result = tools.tool_validate_query(VALID_QUERIES[platform], platform)
    assert result["supported"] is True
    assert result["mode"] == "offline"
    assert result["valid"] is True, result
    assert result["status"] == "passed"
    assert result["errors"] == []
    assert set(result["engine"]) == {"engine"}


def test_validate_query_finds_the_error_in_a_broken_query() -> None:
    result = tools.tool_validate_query(GARBAGE, "sentinel")
    assert result["valid"] is False
    assert result["status"] == "failed"
    assert result["language"] == "kql"
    (error, *_) = result["errors"]
    assert error["severity"] == "error"
    assert error["line"] == 1 and error["column"] >= 1
    assert error["explain"] == f"opentide explain {error['code']}"


def test_validate_query_uses_the_platform_profile() -> None:
    """A Log Analytics table is Sentinel's, not advanced hunting's."""
    query = "NTANetAnalytics | take 1"
    defender = tools.tool_validate_query(query, "defender_for_endpoint")
    sentinel = tools.tool_validate_query(query, "sentinel")
    assert any(item["code"] == "kql_unknown_table" for item in defender["diagnostics"])
    assert not any(item["code"] == "kql_unknown_table" for item in sentinel["diagnostics"])


def test_validate_query_takes_the_elastic_language_and_stack() -> None:
    result = tools.tool_validate_query(
        "FROM logs-* | WHER x == 1", "elastic", language="esql", stack="9.5"
    )
    assert result["language"] == "esql"
    assert result["valid"] is False
    wrong = tools.tool_validate_query("x", "elastic", language="kql")
    assert wrong["valid"] is None
    assert "esql, eql, kuery, lucene" in wrong["message"]


def test_validate_query_refuses_sentinel_one_offline() -> None:
    """S1QL has no offline engine: the check is the tenant's."""
    result = tools.tool_validate_query("EventType = 'Process Creation'", "sentinel_one")
    assert result["supported"] is True
    assert result["valid"] is None
    assert "live: true" in result["message"]


@pytest.mark.parametrize("query", ["", "   "])
def test_validate_query_refuses_an_empty_query(query: str) -> None:
    result = tools.tool_validate_query(query, "splunk")
    assert result["valid"] is None
    assert "empty" in result["message"]


def test_validate_query_live_calls_the_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def _fake(ctx: object, platform: str, *, live: bool = False) -> dict[str, object]:
        seen["platform"] = platform
        seen["live"] = live
        return {"platform": platform, "mode": "live", "status": "passed", "supported": True}

    monkeypatch.setattr("opentide.cli.services.validation.validate_query_platform", _fake)
    result = tools.tool_validate_query("DeviceProcessEvents", "sentinel", live=True)
    assert seen == {"platform": "sentinel", "live": True}
    assert result["mode"] == "live"


@pytest.mark.parametrize("platform", ["crowdstrike", "harfanglab"])
def test_validate_query_never_fakes_an_unsupported_platform(platform: str) -> None:
    result = tools.tool_validate_query("anything at all", platform)
    assert result["supported"] is False
    assert result["valid"] is None
    assert "not supported" in result["message"]


def test_validate_query_truncates_the_preview() -> None:
    result = tools.tool_validate_query("A" * 500, "sentinel_one")
    assert len(result["query_preview"]) == 200


@pytest.mark.parametrize("platform", ["sentinel", "crowdstrike", "harfanglab"])
def test_run_query_refuses_without_live(platform: str) -> None:
    """Without live true no tenant is contacted: an agent must ask a person first."""
    result = tools.tool_run_query("index=*", platform, tenant="prod")
    assert result["supported"] is True
    assert result["status"] == "failed"
    assert "live: true" in result["message"]
    assert "results" not in result
    (action,) = result["next_actions"]
    assert action["tool"] == "run_query"
    assert action["arguments"] == {
        "query": "index=*",
        "platform": platform,
        "live": True,
        "tenant": "prod",
    }
    assert action["command"] == (
        f"opentide --json query --platform {platform} --tenant prod 'index=*'"
    )


def test_run_query_names_the_rule_in_its_next_action() -> None:
    result = tools.tool_run_query("", "splunk", rule="00000000-0000-4000-8003-000000000003")
    (action,) = result["next_actions"]
    assert action["arguments"]["rule"] == "00000000-0000-4000-8003-000000000003"
    assert action["command"].endswith("--rule 00000000-0000-4000-8003-000000000003")


def test_run_query_next_action_keeps_every_choice() -> None:
    """Following the next action must run what the agent asked, not the defaults."""
    result = tools.tool_run_query(
        "process where true",
        "elastic",
        since="7d",
        limit=5,
        language="eql",
        index="logs-*,winlogbeat-*",
    )
    (action,) = result["next_actions"]
    assert action["arguments"] == {
        "query": "process where true",
        "platform": "elastic",
        "live": True,
        "since": "7d",
        "limit": 5,
        "language": "eql",
        "index": "logs-*,winlogbeat-*",
    }
    assert action["command"] == (
        "opentide --json query --platform elastic --since 7d --limit 5 --language eql "
        "--index 'logs-*' --index 'winlogbeat-*' 'process where true'"
    )


def test_run_query_refuses_an_unknown_platform() -> None:
    result = tools.tool_run_query("index=*", "qradar", live=True)
    assert result["supported"] is False
    assert "qradar" in result["message"]


def test_run_query_live_runs_the_cli_service(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def _fake(ctx: object, platform: str, **kwargs: object) -> dict[str, object]:
        seen.update(platform=platform, **kwargs)
        return {
            "platform": platform,
            "status": "completed",
            "results": [],
            "_summary": {"rows": 0},
            "_exit_code": 0,
        }

    monkeypatch.setattr("opentide.cli.services.query.query_platform", _fake)
    result = tools.tool_run_query(
        "SecurityEvent", "sentinel", tenant="prod, lab", live=True, since="7d", limit=5
    )
    assert seen == {
        "platform": "sentinel",
        "query": "SecurityEvent",
        "rule_uuid": None,
        "tenants": ["prod", "lab"],
        "since": "7d",
        "limit": 5,
        "language": None,
        "index": [],
    }
    # The CLI envelope's private keys stay out of the tool payload.
    assert result == {
        "platform": "sentinel",
        "status": "completed",
        "results": [],
        "supported": True,
    }


def test_run_query_default_limit_is_the_row_cap() -> None:
    import inspect

    assert inspect.signature(tools.tool_run_query).parameters["limit"].default == MAX_QUERY_ROWS
