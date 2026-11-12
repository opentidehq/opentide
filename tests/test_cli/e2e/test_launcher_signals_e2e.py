"""Ctrl-C and SIGTERM through the console script (UC-3.8b, #960).

Under ``OPENTIDE_ENGINE=rust`` the console script runs the Rust command line in
its own process. The Python launcher it replaced started a child for each Rust
command and did not forward SIGTERM: ``serve`` and ``mcp start`` ran on,
orphaned, until their input closed. These start the server as a client does,
wait for its first answer, then signal it.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import IO, Any

import pytest

pytestmark = pytest.mark.cli_smoke

#: Each request, one line, and the answer the server is up once it gives.
_FIRST_REQUEST = {
    "serve": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    "mcp": {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "opentide-e2e", "version": "1"},
        },
    },
}


def _console_script() -> list[str]:
    folder = Path(sys.executable).parent
    script = folder / ("opentide.exe" if sys.platform == "win32" else "opentide")
    assert script.is_file(), f"{script}: the console script is not installed (uv sync)"
    return [str(script)]


#: The two ways a person starts opentide.
LAUNCHERS = {
    "console-script": _console_script,
    "python-m": lambda: [sys.executable, "-m", "opentide"],
}


class _Server:
    """A server process, its first answer read, its stdout read to the end in a thread."""

    def __init__(self, argv: list[str], cwd: Path, request: dict[str, Any], **popen: Any) -> None:
        env = {
            name: value
            for name, value in os.environ.items()
            if name not in {"OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"}
        }
        env.update({"OPENTIDE_ENGINE": "rust", "NO_COLOR": "1"})
        self.process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **popen,
        )
        stdin, stdout = self._pipes()
        stdin.write(json.dumps(request).encode() + b"\n")
        stdin.flush()
        first = stdout.readline()
        assert json.loads(first)["id"] == 1, first
        self.rest = b""
        self._reader = threading.Thread(target=self._read_rest, daemon=True)
        self._reader.start()

    def _pipes(self) -> tuple[IO[bytes], IO[bytes]]:
        stdin, stdout = self.process.stdin, self.process.stdout
        assert stdin is not None and stdout is not None
        return stdin, stdout

    def _read_rest(self) -> None:
        self.rest = self._pipes()[1].read()

    def end(self) -> tuple[int, bytes]:
        """The exit code and stderr; stdout must reach its end while stdin is still open.

        A child of the launcher still holding stdout after the launcher exited
        (the old launcher's orphan) would keep the reader waiting.
        """
        code = self.process.wait(timeout=30)
        self._reader.join(timeout=10)
        orphaned = self._reader.is_alive()
        stdin, _ = self._pipes()
        stdin.close()
        stderr = self.process.stderr.read() if self.process.stderr else b""
        self._reader.join(timeout=10)
        assert not orphaned, "stdout stayed open after the launcher exited: a child outlived it"
        return code, stderr


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    from tests.corpus_support import materialise_corpus

    return materialise_corpus(tmp_path / "corpus")


posix = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows has no SIGTERM to handle: os.kill(pid, SIGTERM) there is "
    "TerminateProcess, which ends a process without running any of its code; "
    "Ctrl-C on Windows is test_ctrl_break_on_windows",
)


@posix
@pytest.mark.parametrize("launcher", sorted(LAUNCHERS))
def test_sigterm_reaches_serve(workspace: Path, launcher: str) -> None:
    """``serve`` ends as at the end of its input and exits 128 + 15."""
    server = _Server([*LAUNCHERS[launcher](), "serve"], workspace, _FIRST_REQUEST["serve"])
    server.process.send_signal(signal.SIGTERM)
    code, stderr = server.end()
    assert code == 143, stderr


@posix
@pytest.mark.parametrize("launcher", sorted(LAUNCHERS))
def test_sigterm_reaches_mcp_start(workspace: Path, launcher: str) -> None:
    """The MCP server ends on SIGTERM, as a signal's default does, and leaves nothing running."""
    server = _Server([*LAUNCHERS[launcher](), "mcp", "start"], workspace, _FIRST_REQUEST["mcp"])
    server.process.send_signal(signal.SIGTERM)
    code, stderr = server.end()
    assert code == -signal.SIGTERM, stderr


@posix
@pytest.mark.parametrize("launcher", sorted(LAUNCHERS))
@pytest.mark.parametrize(
    ("command", "request_name"), [(["serve"], "serve"), (["mcp", "start"], "mcp")]
)
def test_ctrl_c_is_error_interrupted_and_130(
    workspace: Path, launcher: str, command: list[str], request_name: str
) -> None:
    server = _Server([*LAUNCHERS[launcher](), *command], workspace, _FIRST_REQUEST[request_name])
    server.process.send_signal(signal.SIGINT)
    code, stderr = server.end()
    assert code == 130, stderr
    assert stderr.decode().splitlines()[-1:] == ["error: interrupted"], stderr


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="CTRL_BREAK_EVENT is Windows' console event; POSIX sends SIGINT above",
)
@pytest.mark.parametrize("launcher", sorted(LAUNCHERS))
def test_ctrl_break_on_windows(workspace: Path, launcher: str) -> None:
    """Ctrl-C's console event reaches ``serve`` in its process: 130, ``error: interrupted``.

    ``GenerateConsoleCtrlEvent`` sends CTRL_C_EVENT only to every process on
    the console, the test runner included, so the server gets a process group
    of its own and CTRL_BREAK_EVENT, which the Rust handler takes as Ctrl-C.
    """
    server = _Server(
        [*LAUNCHERS[launcher](), "serve"],
        workspace,
        _FIRST_REQUEST["serve"],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # type: ignore[attr-defined]
    )
    server.process.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
    code, stderr = server.end()
    assert code == 130, stderr
    assert stderr.decode().splitlines()[-1:] == ["error: interrupted"], stderr
