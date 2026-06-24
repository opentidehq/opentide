"""Tests for setup MCP command module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer

from opentide.cli.enums import McpHost
from opentide.cli.services.setup.mcp import McpSetupOptions, run_mcp_setup, write_mcp_config


@pytest.mark.parametrize(
    ("host", "rel"),
    [
        (McpHost.vscode, ".vscode/mcp.json"),
        (McpHost.cursor, ".cursor/mcp.json"),
        (McpHost.claude_code, ".mcp.json"),
        (McpHost.generic, "opentide.mcp.json"),
    ],
)
def test_write_mcp_config(tmp_path: Path, host: McpHost, rel: str) -> None:
    assert write_mcp_config(tmp_path, host) == rel
    payload = json.loads((tmp_path / rel).read_text(encoding="utf-8"))
    assert payload["mcpServers"]["opentide"]["command"] == "opentide-mcp"


def test_run_mcp_setup_requires_host() -> None:
    with pytest.raises(typer.BadParameter):
        run_mcp_setup(McpSetupOptions(hosts=[]))


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
