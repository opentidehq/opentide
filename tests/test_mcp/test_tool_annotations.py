"""Every MCP tool carries a title and behaviour hints that are true of every argument.

Hosts decide from ``readOnlyHint``, ``destructiveHint`` and ``openWorldHint``
which calls need a person's approval, and Claude's directories review them.
"""

from __future__ import annotations

import asyncio

from mcp.types import Tool

from opentide.mcp_server.server import mcp

#: Tools whose ``live``/``dry_run`` argument makes them contact a tenant.
TENANT_TOOLS = {"validate_query", "run_query", "deploy_rule"}


def _tools() -> dict[str, Tool]:
    return {tool.name: tool for tool in asyncio.run(mcp.list_tools())}


def test_every_tool_has_a_title_and_complete_annotations() -> None:
    for name, tool in _tools().items():
        assert tool.title, name
        hints = tool.annotations
        assert hints is not None, name
        for hint in ("read_only_hint", "destructive_hint", "idempotent_hint", "open_world_hint"):
            assert getattr(hints, hint) is not None, f"{name}.{hint}"
        assert not (hints.read_only_hint and hints.destructive_hint), name


def test_only_tenant_tools_reach_outside_the_workspace() -> None:
    open_world = {
        name
        for name, tool in _tools().items()
        if tool.annotations and tool.annotations.open_world_hint
    }
    assert open_world == TENANT_TOOLS


def test_deploy_rule_is_the_only_destructive_tool() -> None:
    destructive = {
        name
        for name, tool in _tools().items()
        if tool.annotations and tool.annotations.destructive_hint
    }
    assert destructive == {"deploy_rule"}


def test_run_query_is_not_read_only() -> None:
    # Elastic kuery runs a rule preview, which writes alerts to the preview index.
    hints = _tools()["run_query"].annotations
    assert hints is not None
    assert hints.read_only_hint is False


def test_hints_reach_the_wire_in_camel_case() -> None:
    wire = _tools()["deploy_rule"].model_dump(by_alias=True, exclude_none=True)
    assert wire["title"] == "Deploy a rule"
    assert wire["annotations"] == {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    }
