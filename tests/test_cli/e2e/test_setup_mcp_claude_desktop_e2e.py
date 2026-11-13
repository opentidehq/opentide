"""CLI E2E: ``opentide setup mcp --claude-desktop`` writes Claude Desktop's user config (#1036).

Every run points ``HOME``, ``USERPROFILE``, ``APPDATA`` and ``XDG_CONFIG_HOME``
at a temporary folder, so the config lands there on any OS and the real one is
never read or written.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pytest_console_scripts import ScriptRunner
from tests.test_cli.conftest import parse_cli_json
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.setup.mcp import claude_desktop_config_path


def _home_env(tmp_path: Path) -> tuple[dict[str, str], Path]:
    """The variables that place Claude Desktop's config, and where they place it."""
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    config = claude_desktop_config_path(environ=env, home=home)
    assert config.is_relative_to(home)
    return env, config


@pytest.mark.cli_smoke
@pytest.mark.script_launch_mode("subprocess")
def test_setup_mcp_claude_desktop_console_script(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """The installed ``opentide`` writes an entry Claude Desktop can start without a shell."""
    homes, config = _home_env(tmp_path)
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"mcpServers": {"other": {"command": "other-mcp"}}, "theme": "dark"}),
        encoding="utf-8",
    )
    workspace = tmp_path / "detections"
    workspace.mkdir()
    env = {**os.environ, **homes}
    for name in ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"):
        env.pop(name, None)

    result = script_runner.run(
        ["opentide", "--json", "setup", "mcp", "--claude-desktop", "--yes", str(workspace)],
        env=env,
        cwd=tmp_path,
        print_result=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["claude_desktop_config"] == str(config)
    assert payload["files"] == [str(config)]
    assert "Reload MCP Configuration" in payload["advice"]
    written = json.loads(config.read_text(encoding="utf-8"))
    assert written["theme"] == "dark"
    assert written["mcpServers"]["other"] == {"command": "other-mcp"}
    server = written["mcpServers"]["opentide"]
    command = Path(server["command"])
    # The executable that ran setup, by absolute path: Desktop has no shell PATH.
    assert command.is_absolute()
    assert command.is_file()
    assert server["args"][-2:] == ["mcp", "start"]
    assert server["env"] == {"OPENTIDE_REPO_ROOT": str(workspace.resolve())}
    assert list(workspace.iterdir()) == [], "nothing is written in the workspace"

    doctor = script_runner.run(
        ["opentide", "--json", "--repo", str(workspace), "doctor", "--offline"],
        env=env,
        cwd=tmp_path,
        print_result=False,
    )
    checks = {check["code"]: check for check in json.loads(doctor.stdout)["checks"]}
    assert checks["mcp_config"]["status"] == "pass"
    assert checks["mcp_config"]["message"] == "MCP configured for Claude Desktop"


@pytest.mark.cli_e2e
def test_setup_mcp_claude_desktop_human_output_names_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    homes, config = _home_env(tmp_path)
    for name, value in homes.items():
        monkeypatch.setenv(name, value)
    workspace = tmp_path / "detections"
    workspace.mkdir()

    result = CliRunner().invoke(
        app, ["--no-color", "setup", "mcp", "--claude-desktop", "--yes", "--path", str(workspace)]
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    output = " ".join((result.stdout + result.stderr).split())
    assert f"Wrote {config}" in output
    assert "Restart Claude Desktop, or choose Developer → Reload MCP Configuration" in output
    assert config.is_file()


@pytest.mark.cli_e2e
def test_setup_mcp_claude_desktop_malformed_config_is_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    homes, config = _home_env(tmp_path)
    for name, value in homes.items():
        monkeypatch.setenv(name, value)
    config.parent.mkdir(parents=True)
    config.write_text('{"mcpServers": ', encoding="utf-8")

    result = CliRunner().invoke(
        app, ["--json", "setup", "mcp", "--claude-desktop", "--yes", "--path", str(tmp_path)]
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["skipped"] == [str(config)]
    assert payload["files"] == []
    assert any("left unchanged" in warning for warning in payload["warnings"])
    assert config.read_text(encoding="utf-8") == '{"mcpServers": '
