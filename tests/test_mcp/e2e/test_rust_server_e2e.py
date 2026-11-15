"""``opentide mcp start`` in the package's Python process (UC-3.7, #829; UC-6.0c, #841).

The Rust server (rmcp) runs in the package's Python process and answers
every tool and resource itself. The server over stdio, as the ``opentide``
binary runs it, is held by ``crates/opentide-cli/tests/mcp_stdio.rs`` (#1139);
this holds what only the package's process can show: stdout carries
JSON-RPC alone whatever else in that process writes to it.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, materialise_corpus

import opentide

pytestmark = pytest.mark.cli_smoke

PROTOCOL_VERSION = "2024-11-05"
READ_TIMEOUT = 60.0

#: The process ``mcp start`` runs in (the console script, ``opentide._cli.main``),
#: with a thread that writes to descriptor 1 three ways once the server has
#: reserved it (descriptor 1 then points where descriptor 2 does): the
#: descriptor itself, ``print``, and a child process that inherits it.
NOISY_SERVER = """
import os, subprocess, sys, threading, time

def noise():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        one, two = os.fstat(1), os.fstat(2)
        if (one.st_dev, one.st_ino) == (two.st_dev, two.st_ino):
            break
        time.sleep(0.01)
    else:
        return
    os.write(1, b"stray-descriptor\\n")
    print("stray-print", flush=True)
    subprocess.run([sys.executable, "-c", "print('stray-child')"], check=True)
    sys.stderr.write("noise-done\\n")
    sys.stderr.flush()

threading.Thread(target=noise, daemon=True).start()
sys.argv = ["opentide", *sys.argv[1:]]
from opentide._cli import main
raise SystemExit(main())
"""


class StdioClient:
    """A newline-delimited JSON-RPC client of a stdio MCP server."""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self._process = process
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._stderr: list[str] = []
        self._next_id = 0
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        self._errors = threading.Thread(target=self._pump_stderr, daemon=True)
        self._errors.start()

    def _pump_stdout(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _pump_stderr(self) -> None:
        assert self._process.stderr is not None
        for line in self._process.stderr:
            self._stderr.append(line)

    @property
    def stderr(self) -> str:
        return "".join(self._stderr)

    def _send(self, payload: dict[str, Any]) -> None:
        assert self._process.stdin is not None
        self._process.stdin.write(json.dumps(payload) + "\n")
        self._process.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        while True:
            try:
                line = self._lines.get(timeout=READ_TIMEOUT)
            except queue.Empty:
                pytest.fail(f"no response to {method}; stderr:\n{self.stderr}")
            if line is None:
                pytest.fail(f"server closed stdout during {method}; stderr:\n{self.stderr}")
            if not line.strip():
                continue
            envelope = json.loads(line)
            assert envelope["jsonrpc"] == "2.0", f"non JSON-RPC frame on stdout: {line}"
            if envelope.get("id") == request_id:
                return envelope

    def handshake(self) -> dict[str, Any]:
        response = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "opentide-e2e", "version": "1"},
            },
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return response["result"]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        result = self.request("tools/call", {"name": name, "arguments": arguments})["result"]
        assert result.get("isError") is not True, result
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured["result"] if set(structured) == {"result"} else structured
        blocks = [json.loads(block["text"]) for block in result["content"]]
        return blocks[0] if len(blocks) == 1 else blocks

    def close_and_drain(self) -> list[str]:
        """Close stdin, let the server exit, and return every stdout line it still wrote."""
        assert self._process.stdin is not None
        self._process.stdin.close()
        self._process.wait(timeout=READ_TIMEOUT)
        lines: list[str] = []
        while (line := self._lines.get(timeout=READ_TIMEOUT)) is not None:
            lines.append(line)
        self._errors.join(timeout=READ_TIMEOUT)
        return lines


def test_stray_output_in_the_process_never_reaches_the_frames(tmp_path: Path) -> None:
    repo = materialise_corpus(tmp_path / "corpus")
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE", "CLAUDE_PROJECT_DIR"}
    }
    env.update(
        {"CI": "true", "OPENTIDE_REPO_ROOT": str(repo), "OPENTIDE_TIDE_WORKSPACE": str(repo)}
    )
    process = subprocess.Popen(
        [sys.executable, "-c", NOISY_SERVER, "mcp", "start"],
        cwd=repo,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    client = StdioClient(process)
    try:
        # The version the launcher passes the engine: the package's.
        assert client.handshake()["serverInfo"]["version"] == opentide.__version__
        hits = client.call_tool("search", {"query": CORPUS_RULE_UUIDS["sentinel"]})
        assert [hit["uuid"] for hit in hits] == [CORPUS_RULE_UUIDS["sentinel"]]
        report = client.call_tool("validation_report", {})
        assert "next_actions" in report
        deadline = time.monotonic() + 60
        while "noise-done" not in client.stderr and time.monotonic() < deadline:
            client.call_tool("explain", {"code": "vocab_unknown"})
            time.sleep(0.05)
        for line in client.close_and_drain():
            if line.strip():
                assert json.loads(line)["jsonrpc"] == "2.0", line
        for stray in ("stray-descriptor", "stray-print", "stray-child"):
            assert stray in client.stderr, client.stderr
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=15)
