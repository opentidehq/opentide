"""Tests for setup MCP command module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer

from opentide.cli.enums import McpHost
from opentide.cli.services.setup.mcp import McpSetupOptions, run_mcp_setup, write_mcp_config


@pytest.mark.parametrize(
    ("host", "rel", "repo_root"),
    [
        (McpHost.vscode, ".vscode/mcp.json", "${workspaceFolder}"),
        (McpHost.cursor, ".cursor/mcp.json", "${workspaceFolder}"),
        (McpHost.claude_code, ".mcp.json", "${CLAUDE_PROJECT_DIR}"),
        (McpHost.generic, "opentide.mcp.json", None),
    ],
)
def test_write_mcp_config(tmp_path: Path, host: McpHost, rel: str, repo_root: str | None) -> None:
    assert write_mcp_config(tmp_path, host) == rel
    payload = json.loads((tmp_path / rel).read_text(encoding="utf-8"))
    servers = payload.get("servers") if host is McpHost.vscode else payload.get("mcpServers")
    assert isinstance(servers, dict)
    server = servers["opentide"]
    assert isinstance(server, dict)
    assert server["command"] == "opentide-mcp"
    env = server.get("env")
    if repo_root is None:
        assert env is None
        assert "${workspaceFolder}" not in json.dumps(payload)
    else:
        assert isinstance(env, dict)
        assert env["OPENTIDE_REPO_ROOT"] == repo_root
    if host is McpHost.vscode:
        assert "mcpServers" not in payload
    else:
        assert "servers" not in payload


def test_run_mcp_setup_requires_host() -> None:
    with pytest.raises(typer.BadParameter):
        _ = run_mcp_setup(McpSetupOptions(hosts=[]))


def test_run_mcp_setup_multiple_hosts(tmp_path: Path) -> None:
    result = run_mcp_setup(
        McpSetupOptions(
            path=tmp_path,
            hosts=[McpHost.vscode, McpHost.cursor],
            yes=True,
        )
    )
    assert set(result["files"]) == {".vscode/mcp.json", ".cursor/mcp.json"}


def test_run_mcp_setup_generic_note(tmp_path: Path) -> None:
    result = run_mcp_setup(McpSetupOptions(path=tmp_path, hosts=[McpHost.generic], yes=True))
    assert "note" in result
