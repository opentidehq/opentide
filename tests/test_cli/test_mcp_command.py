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


def test_start_missing_mcp_prints_repair_line_on_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "opentide.mcp_server.launcher.probe",
        lambda: (
            "opentide mcp start cannot import mcp.server.mcpserver, but mcp ships as a "
            "base dependency of opentide — this environment is incomplete.\n"
            "Repair it with:  pip install 'mcp>=2.3,<3'\n"
        ),
    )
    result = runner.invoke(app, ["mcp", "start"])
    assert result.exit_code == 1
    assert "pip install 'mcp>=2.3,<3'" in result.stderr
    assert result.stdout.strip() == ""
    assert "jsonrpc" not in result.stdout
    assert "Traceback" not in result.stderr


def test_probe_names_mcp_start_when_mcpserver_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib

    real_import = importlib.import_module

    def boom(name: str) -> object:
        if name == "mcp.server.mcpserver":
            raise ImportError(name)
        return real_import(name)

    monkeypatch.setattr("opentide.mcp_server.launcher._package_installed", lambda _name: False)
    monkeypatch.setattr("opentide.mcp_server.launcher.importlib.import_module", boom)
    text = probe()
    assert text is not None
    assert text.startswith("opentide mcp start cannot import mcp.server.mcpserver")
    assert "pip install 'mcp>=2.3,<3'" in text
    assert "opentide-mcp" not in text
    # mcp is a base dependency since 0.14.0, so the [mcp] extra is an empty
    # alias: advising it would install nothing and strand the user.
    assert "opentide[mcp]" not in text


def test_probe_names_mcp_start_when_mcp_1_lacks_mcpserver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    real_import = importlib.import_module

    def boom(name: str) -> object:
        if name == "mcp.server.mcpserver":
            raise ImportError("No module named mcp.server.mcpserver")
        return real_import(name)

    monkeypatch.setattr("opentide.mcp_server.launcher._package_installed", lambda _name: True)
    monkeypatch.setattr("opentide.mcp_server.launcher.importlib.import_module", boom)
    text = probe()
    assert text is not None
    assert text.startswith("opentide mcp start cannot use the installed mcp package")
    assert "pip install 'mcp>=2.3,<3'" in text
    assert "opentide-mcp" not in text
    assert "opentide[mcp]" not in text


def test_server_main_forces_json_logging_after_cli_init(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The root callback installs Rich logging. start must replace it before run."""
    init_logging(LoggingConfig(json_output=False, plain=False), force=True)

    async def fake_serve() -> None:
        logging.getLogger("opentide.mcp.stdio").warning("mcp_ready")

    monkeypatch.setattr("opentide.mcp_server.server.serve_stdio", fake_serve)
    from opentide.cli.ui.mode import OutputMode, get_mode
    from opentide.core.logging.config import current_config
    from opentide.mcp_server.server import main as serve

    try:
        serve()
        assert get_mode() is OutputMode.MCP
        assert current_config().json_output is True
        assert current_config().plain is True
        err = capsys.readouterr().err
    finally:
        init_logging(LoggingConfig(), force=True)
    line = next(item for item in err.splitlines() if "mcp_ready" in item)
    payload = json.loads(line)
    assert payload["event"] == "mcp_ready"


_STRAY_WRITERS = """
import subprocess, sys
from opentide.mcp_server.server import reserve_stdout

with reserve_stdout() as rpc:
    print("stray print")
    sys.stdout.flush()
    subprocess.run([sys.executable, "-c", "print('child process')"], check=True)
    rpc.write('{"jsonrpc": "2.0"}\\n')
print("after the server")
"""


def test_reserve_stdout_sends_every_other_writer_to_stderr() -> None:
    """A print, a Rich console or a child process must not corrupt a JSON-RPC frame."""
    done = subprocess.run(
        [sys.executable, "-c", _STRAY_WRITERS],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert done.stdout == '{"jsonrpc": "2.0"}\nafter the server\n'
    assert "stray print" in done.stderr
    assert "child process" in done.stderr
