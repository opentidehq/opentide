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
    assert server["command"] == "opentide"
    assert server["args"] == ["mcp", "start"]
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


def test_run_mcp_setup_generic_advice(tmp_path: Path) -> None:
    result = run_mcp_setup(McpSetupOptions(path=tmp_path, hosts=[McpHost.generic], yes=True))
    assert "Copy opentide.mcp.json into your editor MCP settings" in str(result["advice"])


@pytest.mark.parametrize(
    ("host", "key"),
    [
        (McpHost.vscode, "servers"),
        (McpHost.cursor, "mcpServers"),
        (McpHost.claude_code, "mcpServers"),
    ],
)
def test_write_mcp_config_keeps_the_users_other_servers(
    tmp_path: Path, host: McpHost, key: str
) -> None:
    """The template was written over the file, dropping every other MCP server."""
    dest = tmp_path / write_mcp_config(tmp_path, host)
    dest.write_text(
        "{\n  // JSONC, as VS Code writes it\n"
        f'  "inputs": [{{"id": "token"}}],\n'
        f'  "{key}": {{"other": {{"command": "other-mcp"}},}}\n}}\n',
        encoding="utf-8",
    )

    write_mcp_config(tmp_path, host)

    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert payload["inputs"] == [{"id": "token"}]
    assert payload[key]["other"] == {"command": "other-mcp"}
    assert payload[key]["opentide"]["args"] == ["mcp", "start"]


@pytest.mark.parametrize(
    "existing",
    ["{not json", "[]", '{"mcpServers": ["opentide"]}'],
    ids=["invalid", "not-an-object", "servers-not-an-object"],
)
def test_run_mcp_setup_leaves_a_config_it_cannot_merge(tmp_path: Path, existing: str) -> None:
    (tmp_path / ".mcp.json").write_text(existing, encoding="utf-8")

    result = run_mcp_setup(
        McpSetupOptions(path=tmp_path, hosts=[McpHost.claude_code, McpHost.cursor], yes=True)
    )

    assert (tmp_path / ".mcp.json").read_text(encoding="utf-8") == existing
    assert result["files"] == [".cursor/mcp.json"]
    assert result["skipped"] == [".mcp.json"]
    warnings = result["warnings"]
    assert isinstance(warnings, list)
    assert any(str(warning).startswith(".mcp.json ") for warning in warnings)


AGENT_PLUGINS_MCP_SCHEMA = (
    Path(__file__).resolve().parents[1] / "fixtures" / "agent_plugins" / "mcp.schema.json"
)


def test_generic_config_is_an_agent_plugins_mcp_json(tmp_path: Path) -> None:
    """#431: the portable config validates against Agent Plugins 1.0.0, which
    requires `$schema` and `type` and rejects any other top-level key."""
    from jsonschema import Draft202012Validator

    schema = json.loads(AGENT_PLUGINS_MCP_SCHEMA.read_text(encoding="utf-8"))
    payload = json.loads((tmp_path / write_mcp_config(tmp_path, McpHost.generic)).read_text())

    Draft202012Validator(schema).validate(payload)
    assert payload["mcpServers"]["opentide"] == {
        "type": "stdio",
        "command": "opentide",
        "args": ["mcp", "start"],
    }


def test_write_mcp_config_keeps_the_users_schema_key(tmp_path: Path) -> None:
    """A scalar the user set, such as `$schema`, is neither overwritten nor an error."""
    dest = tmp_path / "opentide.mcp.json"
    dest.write_text('{"$schema": "https://example.test/mcp.json"}', encoding="utf-8")

    write_mcp_config(tmp_path, McpHost.generic)

    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert payload["$schema"] == "https://example.test/mcp.json"
    assert payload["mcpServers"]["opentide"]["type"] == "stdio"
