"""The Python half of the Rust MCP server (``opentide.mcp_server.bridge``, UC-3.7, #829).

The Rust server hands the tools and resources it has no implementation of to
the Python server's own handlers, in its process: what it gets back must be
what the Python server sends on the wire. The recorded sessions
(``cargo xtask mcp replay``) hold that over stdio; these hold the bridge's own
contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS

from opentide.mcp_server import bridge, workspace

ROOT = Path(__file__).resolve().parents[2]


def test_the_manifest_the_rust_server_compiles_in_is_current() -> None:
    """``scripts/build/mcp_manifest.py`` wrote it from the server as it is now."""
    committed = json.loads((ROOT / bridge.MANIFEST_PATH).read_text(encoding="utf-8"))
    assert committed == bridge.manifest(), (
        f"{bridge.MANIFEST_PATH} is stale: run uv run python scripts/build/mcp_manifest.py"
    )


def test_the_manifest_is_what_the_server_says_of_itself() -> None:
    from opentide.mcp_server.server import INSTRUCTIONS, TAGLINE, mcp

    manifest = bridge.manifest()
    assert manifest["name"] == "opentide"
    assert manifest["instructions"] == INSTRUCTIONS
    assert TAGLINE in manifest["instructions"]
    names = [tool["name"] for tool in manifest["tools"]]
    assert names == [tool.name for tool in mcp._tool_manager.list_tools()]
    for tool in manifest["tools"]:
        assert tool["inputSchema"]["type"] == "object", tool["name"]
    uris = {item["uri"] for item in manifest["resources"]}
    assert "opentide://index" in uris
    templates = {item["uriTemplate"] for item in manifest["resourceTemplates"]}
    assert "opentide://vocabularies/{+name}" in templates
    # An empty extensions map is not part of the handshake's capabilities.
    assert "extensions" not in manifest["capabilities"]
    assert manifest["protocolVersion"] == "2025-11-25"


def test_a_tool_call_is_the_wire_result(tide_corpus_repo: Path) -> None:
    answer = json.loads(
        bridge.call_tool("search", json.dumps({"query": CORPUS_RULE_UUIDS["sentinel"]}))
    )
    result = answer["result"]
    hits = result["structuredContent"]["result"]
    assert [hit["uuid"] for hit in hits] == [CORPUS_RULE_UUIDS["sentinel"]]
    assert [json.loads(block["text"]) for block in result["content"]] == hits
    assert result["isError"] is False


def test_a_tool_that_fails_is_an_error_result_not_an_error() -> None:
    answer = json.loads(bridge.call_tool("explain", json.dumps({"code": 5})))
    assert answer["result"]["isError"] is True
    assert "validation error" in answer["result"]["content"][0]["text"]
    unknown = json.loads(bridge.call_tool("no_such_tool", "{}"))
    assert unknown["result"]["content"][0]["text"] == "Unknown tool: no_such_tool"


def test_an_unknown_resource_is_a_json_rpc_error(tide_corpus_repo: Path) -> None:
    answer = json.loads(bridge.read_resource("opentide://nothing"))
    assert answer == {
        "error": {
            "code": -32602,
            "message": "Unknown resource: opentide://nothing",
            "data": {"uri": "opentide://nothing"},
        }
    }
    platforms = json.loads(bridge.read_resource("opentide://platforms"))["result"]
    (contents,) = platforms["contents"]
    assert contents["uri"] == "opentide://platforms"
    assert {entry["name"] for entry in json.loads(contents["text"])} >= {"sentinel"}


def test_the_workspace_problem_is_the_refusal_the_catalogue_tools_give(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(workspace, "_problem", None)
    assert bridge.workspace_problem() is None
    monkeypatch.setattr(workspace, "_problem", "workspace_not_found: name one")
    assert bridge.workspace_problem() == "workspace_not_found: name one"
    answer = json.loads(bridge.call_tool("search", json.dumps({"query": ""})))
    assert answer["result"]["isError"] is True
    text = answer["result"]["content"][0]["text"]
    assert text == "Error executing tool search: workspace_not_found: name one"


def test_start_applies_the_plugin_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Started in an Agent Plugin root that names no workspace, the problem is remembered."""
    plugin = tmp_path / "plugin"
    (plugin / ".git").mkdir(parents=True)
    (plugin / "plugin.json").write_text(
        json.dumps({"$schema": f"{workspace.AGENT_PLUGINS_SCHEMA}1.0.0/plugin.schema.json"}),
        encoding="utf-8",
    )
    for name in (*workspace.WORKSPACE_VARIABLES, *workspace.HOST_PROJECT_VARIABLES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(plugin)
    monkeypatch.setattr(workspace, "_problem", None)
    bridge.start()
    problem = bridge.workspace_problem()
    assert problem is not None and problem.startswith("workspace_not_found")
