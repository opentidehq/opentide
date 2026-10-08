"""``opentide mcp`` is the stdio server. ``opentide-mcp`` is not a command."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.core.logging import LoggingConfig, init_logging
from opentide.mcp_server.launcher import probe

runner = CliRunner()


def test_mcp_group_prints_help_and_exits() -> None:
    """No subcommand must print help. It must not become the stdio server."""
    done = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys\nfrom opentide.cli import main\nsys.argv = ['opentide', 'mcp']\nmain()\n",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env={**os.environ, "NO_COLOR": "1"},
    )
    text = done.stdout + done.stderr
    assert done.returncode != 124, text
    assert "start" in text
    commands = text.split("Commands", 1)[-1]
    assert "start" in commands
    assert "reload" not in commands
    assert "stop" not in commands
    assert "closing stdin" in text
    assert "jsonrpc" not in done.stdout


def test_mcp_help_lists_start_only() -> None:
    result = runner.invoke(app, ["mcp", "--help"])
    assert result.exit_code == 0
    text = result.stdout + result.stderr
    commands = text.split("Commands", 1)[-1]
    assert "start" in commands
    assert "reload" not in commands
    assert "stop" not in commands
    assert "closing stdin" in text


@pytest.mark.parametrize("verb", ["reload", "stop"])
def test_mcp_has_no_lifecycle_verb(verb: str) -> None:
    result = runner.invoke(app, ["mcp", verb])
    assert result.exit_code != 0
    assert "jsonrpc" not in result.stdout


def test_start_missing_extra_prints_install_line_on_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "opentide.mcp_server.launcher.probe",
        lambda: (
            "opentide mcp start needs the MCP extra, which is not installed "
            "(missing: mcp.server.fastmcp).\n"
            "Install it with:  pip install 'opentide[mcp]'\n"
        ),
    )
    result = runner.invoke(app, ["mcp", "start"])
    assert result.exit_code == 1
    assert "pip install 'opentide[mcp]'" in result.stderr
    assert result.stdout.strip() == ""
    assert "jsonrpc" not in result.stdout
    assert "Traceback" not in result.stderr


def test_probe_names_mcp_start_when_fastmcp_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib

    real_import = importlib.import_module

    def boom(name: str) -> object:
        if name == "mcp.server.fastmcp":
            raise ImportError(name)
        return real_import(name)

    monkeypatch.setattr("opentide.mcp_server.launcher._package_installed", lambda _name: False)
    monkeypatch.setattr("opentide.mcp_server.launcher.importlib.import_module", boom)
    text = probe()
    assert text is not None
    assert text.startswith("opentide mcp start needs the MCP extra")
    assert "pip install 'opentide[mcp]'" in text
    assert "opentide-mcp" not in text


def test_probe_names_mcp_start_when_mcp_2_replaced_fastmcp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    real_import = importlib.import_module

    def boom(name: str) -> object:
        if name == "mcp.server.fastmcp":
            raise ImportError("server.fastmcp was removed")
        return real_import(name)

    monkeypatch.setattr("opentide.mcp_server.launcher._package_installed", lambda _name: True)
    monkeypatch.setattr("opentide.mcp_server.launcher.importlib.import_module", boom)
    text = probe()
    assert text is not None
    assert text.startswith("opentide mcp start cannot use the installed mcp package")
    assert "pip install 'opentide[mcp]'" in text
    assert "opentide-mcp" not in text


def test_server_main_forces_json_logging_after_cli_init(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The root callback installs Rich logging. start must replace it before run."""
    init_logging(LoggingConfig(json_output=False, plain=False), force=True)

    def fake_run(*, transport: str) -> None:
        assert transport == "stdio"
        logging.getLogger("opentide.mcp.stdio").warning("mcp_ready")

    monkeypatch.setattr("opentide.mcp_server.server.mcp.run", fake_run)
    from opentide.core.logging.config import current_config
    from opentide.mcp_server.server import main as serve

    try:
        serve()
        assert current_config().json_output is True
        assert current_config().plain is True
        err = capsys.readouterr().err
    finally:
        init_logging(LoggingConfig(), force=True)
    line = next(item for item in err.splitlines() if "mcp_ready" in item)
    payload = json.loads(line)
    assert payload["event"] == "mcp_ready"
