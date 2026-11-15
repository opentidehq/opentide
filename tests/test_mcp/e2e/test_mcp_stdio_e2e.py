"""End-to-end JSON-RPC exercise of ``opentide mcp start`` (#264, #460).

Everything else under ``tests/test_mcp/`` calls tool functions in-process. This
module spawns the published console script and speaks the newline-delimited
JSON-RPC that the mcp SDK actually implements, so transport regressions (framing,
log bleed onto stdout, missing ``mcp`` dependency) surface in CI.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    corpus_env,
    materialise_corpus,
)

pytestmark = pytest.mark.cli_smoke

PROTOCOL_VERSION = "2024-11-05"
READ_TIMEOUT = 60.0

EXPECTED_TOOLS = {
    "search",
    "get_chaining",
    "coverage",
    "validate_rule",
    "validation_report",
    "explain",
    "validate_query",
    "run_query",
    "deploy_rule",
    "deployment_status",
}


def _server_argv() -> list[str]:
    # The script beside this interpreter runs the code under test; another one
    # earlier on PATH may belong to an older install.
    candidate = Path(sys.executable).with_name("opentide")
    resolved = str(candidate) if candidate.exists() else shutil.which("opentide")
    if resolved is None:
        pytest.skip("opentide console script is not installed")
    return [resolved, "mcp", "start"]


class StdioClient:
    """Minimal newline-delimited JSON-RPC client for a stdio MCP server."""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self._process = process
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._stderr: list[str] = []
        self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
        self._reader.start()
        self._errors = threading.Thread(target=self._pump_stderr, daemon=True)
        self._errors.start()
        self._next_id = 0

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

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

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
            text = line.strip()
            if not text:
                continue
            envelope = json.loads(text)
            assert envelope["jsonrpc"] == "2.0", f"non JSON-RPC frame on stdout: {text}"
            if envelope.get("id") == request_id:
                return envelope

    def close_and_drain(self) -> list[str]:
        """Close stdin, let the server exit, and return every stdout line it still wrote."""
        assert self._process.stdin is not None
        self._process.stdin.close()
        self._process.wait(timeout=READ_TIMEOUT)
        lines: list[str] = []
        while (line := self._lines.get(timeout=READ_TIMEOUT)) is not None:
            lines.append(line)
        # Everything the server wrote to stderr is read too.
        self._errors.join(timeout=READ_TIMEOUT)
        return lines

    def handshake(self) -> dict[str, Any]:
        response = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "opentide-e2e", "version": "1"},
            },
        )
        self.notify("notifications/initialized")
        return response

    def raw_tool_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.request("tools/call", {"name": name, "arguments": arguments})
        result = response["result"]
        assert result.get("isError") is not True, result
        return result

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        result = self.raw_tool_call(name, arguments)
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            # MCPServer wraps non-object returns (our list-shaped tools) in "result".
            return structured["result"] if set(structured) == {"result"} else structured
        blocks = [json.loads(block["text"]) for block in result["content"]]
        return blocks[0] if len(blocks) == 1 else blocks

    def read_resource(self, uri: str) -> Any:
        response = self.request("resources/read", {"uri": uri})
        contents = response["result"]["contents"]
        assert contents, f"no contents for {uri}"
        return json.loads(contents[0]["text"])


def test_content_length_headers_are_skipped_and_the_body_is_answered(tmp_path: Path) -> None:
    """MCP stdio is newline-delimited: LSP-style headers are not frames.

    mcp 2.x drops a line that does not parse as JSON-RPC (it logs it at debug
    and sends nothing; 1.x answered with an error notification). The body still
    parses because it is a line of its own, so a Content-Length client gets its
    ``initialize`` answer, and the header lines leave nothing but JSON-RPC on
    stdout.
    """
    repo = materialise_corpus(tmp_path / "corpus")
    env = {**os.environ, **corpus_env(repo), "CI": "true"}
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "lsp-style", "version": "1"},
            },
        }
    )
    framed = f"Content-Length: {len(body)}\r\n\r\n{body}"
    process = subprocess.run(
        _server_argv(),
        cwd=repo,
        env=env,
        input=framed,
        capture_output=True,
        text=True,
        timeout=READ_TIMEOUT,
    )
    frames = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    assert frames, "expected the initialize response on the NDJSON stream"
    assert all(frame["jsonrpc"] == "2.0" for frame in frames)
    responses = [frame for frame in frames if frame.get("id") == 1]
    assert responses and responses[0]["result"]["serverInfo"]["name"] == "opentide"


# Started by an Agent Plugins client (#431): the cwd is the plugin root.


def _plugin_root(path: Path) -> Path:
    (path / "skills").mkdir(parents=True)
    (path / ".git").mkdir()
    (path / "plugin.json").write_text(
        json.dumps(
            {
                "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
                "name": "opentide",
            }
        ),
        encoding="utf-8",
    )
    return path


def _plugin_launch(plugin: Path, extra: dict[str, str]) -> subprocess.Popen[str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE", "CLAUDE_PROJECT_DIR"}
    }
    env.update({"CI": "true", "PWD": str(plugin), **extra})
    return subprocess.Popen(
        _server_argv(),
        cwd=plugin,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def test_a_plugin_launch_serves_the_host_project(tmp_path: Path) -> None:
    repo = materialise_corpus(tmp_path / "corpus")
    plugin = _plugin_root(tmp_path / "skills")
    process = _plugin_launch(plugin, {"CLAUDE_PROJECT_DIR": str(repo)})
    client = StdioClient(process)
    client.handshake()
    payload = client.call_tool("search", {"query": CORPUS_RULE_UUIDS["sentinel"]})
    assert [hit["uuid"] for hit in payload] == [CORPUS_RULE_UUIDS["sentinel"]]
    client.close_and_drain()


def test_a_plugin_launch_without_a_workspace_says_how_to_name_one(tmp_path: Path) -> None:
    plugin = _plugin_root(tmp_path / "skills")
    process = _plugin_launch(plugin, {})
    client = StdioClient(process)
    client.handshake()
    result = client.request("tools/call", {"name": "search", "arguments": {"query": ""}})
    assert result["result"]["isError"] is True
    text = result["result"]["content"][0]["text"]
    assert "workspace_not_found" in text and "OPENTIDE_REPO_ROOT" in text
    # Tools that need no catalogue still work.
    explained = client.call_tool("explain", {"code": "workspace_not_found"})
    assert isinstance(explained, dict)
    client.close_and_drain()
