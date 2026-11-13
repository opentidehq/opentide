"""Tests for setup MCP command module."""

from __future__ import annotations

import json
import os
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


def test_setup_mcp_vscode_says_when_the_extension_provides_the_server(tmp_path: Path) -> None:
    """#752: the extension serves opentide's MCP server; mcp.json is for teammates without it."""
    plain = run_mcp_setup(McpSetupOptions(path=tmp_path, hosts=[McpHost.vscode]))
    assert "extension_mcp" not in plain
    (tmp_path / ".vscode" / "extensions.json").write_text(
        '{"recommendations": ["opentidehq.opentide"]}', encoding="utf-8"
    )
    result = run_mcp_setup(McpSetupOptions(path=tmp_path, hosts=[McpHost.vscode]))
    assert result["files"] == [".vscode/mcp.json"]
    assert result["extension_mcp"] is True
    assert "opentidehq.opentide" in str(result["detail"])
    assert "teammates without it" in str(result["detail"])
    other = run_mcp_setup(McpSetupOptions(path=tmp_path, hosts=[McpHost.cursor]))
    assert "extension_mcp" not in other


# --------------------------------------------------------------------------- Claude Desktop (#1036)


@pytest.mark.parametrize(
    ("platform", "environ", "parts"),
    [
        ("darwin", {}, ("home", "Library", "Application Support")),
        ("darwin", {"XDG_CONFIG_HOME": "xdg"}, ("home", "Library", "Application Support")),
        ("win32", {"APPDATA": "roaming"}, ("roaming",)),
        ("win32", {}, ("home", "AppData", "Roaming")),
        ("linux", {}, ("home", ".config")),
        ("linux", {"XDG_CONFIG_HOME": "xdg"}, ("xdg",)),
        ("freebsd14", {}, ("home", ".config")),
    ],
    ids=[
        "macos",
        "macos-ignores-xdg",
        "windows-appdata",
        "windows-no-appdata",
        "linux",
        "linux-xdg",
        "other",
    ],
)
def test_claude_desktop_config_path_per_os(
    tmp_path: Path, platform: str, environ: dict[str, str], parts: tuple[str, ...]
) -> None:
    from opentide.cli.services.setup.mcp import claude_desktop_config_path

    # Absolute values under tmp_path, so the test reads the same on every OS.
    absolute = {key: str(tmp_path / value) for key, value in environ.items()}

    path = claude_desktop_config_path(platform, absolute, tmp_path / "home")

    assert path == tmp_path.joinpath(*parts, "Claude", "claude_desktop_config.json")


@pytest.mark.parametrize("xdg", ["", "relative/xdg"])
def test_claude_desktop_config_path_ignores_an_unusable_xdg_config_home(
    tmp_path: Path, xdg: str
) -> None:
    """The XDG specification: a relative ``XDG_CONFIG_HOME`` is invalid and ignored."""
    from opentide.cli.services.setup.mcp import claude_desktop_config_path

    path = claude_desktop_config_path("linux", {"XDG_CONFIG_HOME": xdg}, tmp_path)

    assert path == tmp_path / ".config" / "Claude" / "claude_desktop_config.json"


def test_opentide_command_prefers_the_script_beside_the_interpreter(tmp_path: Path) -> None:
    from opentide.cli.services.setup.mcp import opentide_command

    python = tmp_path / "venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("", encoding="utf-8")
    (python.parent / "opentide").write_text("", encoding="utf-8")

    command = opentide_command(str(python), which=lambda _: "/elsewhere/opentide", platform="linux")

    assert command == (str(python.parent / "opentide"), ["mcp", "start"])
    assert Path(command[0]).is_absolute()


def test_opentide_command_on_windows_looks_for_the_exe(tmp_path: Path) -> None:
    from opentide.cli.services.setup.mcp import opentide_command

    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    (scripts / "opentide.exe").write_text("", encoding="utf-8")

    program, args = opentide_command(
        str(scripts / "python.exe"), which=lambda _: None, platform="win32"
    )

    assert program == str(scripts / "opentide.exe")
    assert args == ["mcp", "start"]


def test_opentide_command_falls_back_to_path_then_to_the_interpreter(tmp_path: Path) -> None:
    from opentide.cli.services.setup.mcp import opentide_command

    python = tmp_path / "bin" / "python"
    on_path = tmp_path / "local" / "opentide"

    assert opentide_command(str(python), which=lambda _: str(on_path), platform="linux") == (
        str(on_path),
        ["mcp", "start"],
    )
    assert opentide_command(str(python), which=lambda _: None, platform="linux") == (
        str(python),
        ["-m", "opentide", "mcp", "start"],
    )


@pytest.fixture
def desktop_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Claude Desktop's config under a temporary home, on whatever OS runs the test."""
    from opentide.cli.services.setup.mcp import claude_desktop_config_path

    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    path = claude_desktop_config_path()
    assert path.is_relative_to(home)
    return path


def test_setup_mcp_claude_desktop_writes_an_absolute_entry(
    tmp_path: Path, desktop_config: Path
) -> None:
    workspace = tmp_path / "detections"
    workspace.mkdir()

    result = run_mcp_setup(
        McpSetupOptions(path=workspace, hosts=[McpHost.claude_desktop], yes=True)
    )

    # The folders are created: Claude Desktop may never have run.
    payload = json.loads(desktop_config.read_text(encoding="utf-8"))
    server = payload["mcpServers"]["opentide"]
    assert Path(server["command"]).is_absolute()
    assert server["args"][-2:] == ["mcp", "start"]
    assert server["env"] == {"OPENTIDE_REPO_ROOT": str(workspace.resolve())}
    assert result["files"] == [str(desktop_config)]
    assert result["claude_desktop_config"] == str(desktop_config)
    assert "Reload MCP Configuration" in str(result["advice"])
    assert "skipped" not in result
    assert not (workspace / ".mcp.json").exists()


def test_setup_mcp_claude_desktop_keeps_other_servers_and_replaces_opentide(
    tmp_path: Path, desktop_config: Path
) -> None:
    desktop_config.parent.mkdir(parents=True)
    desktop_config.write_text(
        json.dumps(
            {
                "globalShortcut": "Ctrl+Space",
                "mcpServers": {
                    "filesystem": {"command": "npx", "args": ["-y", "server-filesystem"]},
                    "opentide": {"command": "opentide", "args": ["mcp", "start"], "cwd": "/old"},
                },
            }
        ),
        encoding="utf-8",
    )

    run_mcp_setup(McpSetupOptions(path=tmp_path, hosts=[McpHost.claude_desktop], yes=True))

    payload = json.loads(desktop_config.read_text(encoding="utf-8"))
    assert payload["globalShortcut"] == "Ctrl+Space"
    assert payload["mcpServers"]["filesystem"] == {
        "command": "npx",
        "args": ["-y", "server-filesystem"],
    }
    opentide = payload["mcpServers"]["opentide"]
    assert "cwd" not in opentide, "the old entry was merged into, not replaced"
    assert opentide["env"]["OPENTIDE_REPO_ROOT"] == str(tmp_path.resolve())


@pytest.mark.parametrize(
    "existing",
    ["{not json", "[]", '{"mcpServers": ["opentide"]}'],
    ids=["invalid", "not-an-object", "servers-not-an-object"],
)
def test_setup_mcp_claude_desktop_leaves_a_config_it_cannot_merge(
    tmp_path: Path, desktop_config: Path, existing: str
) -> None:
    desktop_config.parent.mkdir(parents=True)
    desktop_config.write_text(existing, encoding="utf-8")

    result = run_mcp_setup(
        McpSetupOptions(path=tmp_path, hosts=[McpHost.claude_desktop, McpHost.cursor], yes=True)
    )

    assert desktop_config.read_text(encoding="utf-8") == existing
    assert result["files"] == [".cursor/mcp.json"]
    assert result["skipped"] == [str(desktop_config)]
    assert "claude_desktop_config" not in result
    warnings = result["warnings"]
    assert isinstance(warnings, list)
    assert any(
        str(warning).startswith(f"{desktop_config} ") and "left unchanged" in str(warning)
        for warning in warnings
    )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symbolic links")
def test_setup_mcp_claude_desktop_writes_through_a_link(
    tmp_path: Path, desktop_config: Path
) -> None:
    """A dotfile manager's link stays a link: the file it points at is merged."""
    dotfiles = tmp_path / "dotfiles" / "claude.json"
    dotfiles.parent.mkdir()
    dotfiles.write_text('{"mcpServers": {"other": {"command": "x"}}}', encoding="utf-8")
    desktop_config.parent.mkdir(parents=True)
    try:
        desktop_config.symlink_to(dotfiles)
    except OSError:
        pytest.skip("cannot create symbolic links here")

    result = run_mcp_setup(McpSetupOptions(path=tmp_path, hosts=[McpHost.claude_desktop]))

    assert desktop_config.is_symlink()
    payload = json.loads(dotfiles.read_text(encoding="utf-8"))
    assert set(payload["mcpServers"]) == {"other", "opentide"}
    assert result["claude_desktop_config"] == str(dotfiles.resolve())


def test_setup_mcp_claude_desktop_plan_writes_nothing(tmp_path: Path, desktop_config: Path) -> None:
    result = run_mcp_setup(
        McpSetupOptions(path=tmp_path, hosts=[McpHost.claude_desktop], yes=True, plan=True)
    )
    assert not desktop_config.exists()
    assert not desktop_config.parent.exists()
    assert result["_outside"] == [{"path": str(desktop_config), "action": "create"}]

    desktop_config.parent.mkdir(parents=True)
    desktop_config.write_text("{}", encoding="utf-8")
    merged = run_mcp_setup(
        McpSetupOptions(path=tmp_path, hosts=[McpHost.claude_desktop], plan=True)
    )
    assert desktop_config.read_text(encoding="utf-8") == "{}"
    assert merged["_outside"] == [{"path": str(desktop_config), "action": "merge"}]

    desktop_config.write_text("[]", encoding="utf-8")
    broken = run_mcp_setup(
        McpSetupOptions(path=tmp_path, hosts=[McpHost.claude_desktop], plan=True)
    )
    assert broken["_outside"] == [{"path": str(desktop_config), "action": "skip"}]
    assert "skipped" not in broken


def test_write_mcp_config_refuses_claude_desktop(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not in the repository"):
        write_mcp_config(tmp_path, McpHost.claude_desktop)


def test_setup_mcp_claude_desktop_warns_when_the_config_cannot_be_written(
    tmp_path: Path, desktop_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A folder outside the repository this user cannot write is a warning, not a crash."""
    import opentide.core.io

    def refuse(path: Path, content: str) -> None:
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(opentide.core.io, "write_text_atomically", refuse)

    result = run_mcp_setup(
        McpSetupOptions(path=tmp_path, hosts=[McpHost.claude_desktop, McpHost.cursor], yes=True)
    )

    assert result["files"] == [".cursor/mcp.json"]
    assert result["skipped"] == [str(desktop_config)]
    assert f"{desktop_config} could not be written (Permission denied)" in str(result["warnings"])
    assert "claude_desktop_config" not in result
