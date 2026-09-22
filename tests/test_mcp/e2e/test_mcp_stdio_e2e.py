"""End-to-end JSON-RPC exercise of the ``opentide-mcp`` console script (#264).

Everything else under ``tests/test_mcp/`` calls tool functions in-process. This
module spawns the published console script and speaks the newline-delimited
JSON-RPC that FastMCP actually implements, so transport regressions (framing,
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
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    CORPUS_TECHNIQUE,
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
    "validate_query",
    "run_query",
    "deploy_rule",
    "deployment_status",
}


def _console_script() -> str:
    # The script beside this interpreter runs the code under test; another one
    # earlier on PATH may belong to an older install.
    candidate = Path(sys.executable).with_name("opentide-mcp")
    resolved = str(candidate) if candidate.exists() else shutil.which("opentide-mcp")
    if resolved is None:
        pytest.skip("opentide-mcp console script is not installed")
    return resolved


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
            # FastMCP wraps non-object returns (our list-shaped tools) in "result".
            return structured["result"] if set(structured) == {"result"} else structured
        blocks = [json.loads(block["text"]) for block in result["content"]]
        return blocks[0] if len(blocks) == 1 else blocks

    def read_resource(self, uri: str) -> Any:
        response = self.request("resources/read", {"uri": uri})
        contents = response["result"]["contents"]
        assert contents, f"no contents for {uri}"
        return json.loads(contents[0]["text"])


@pytest.fixture
def mcp_stdio(tmp_path: Path) -> Iterator[StdioClient]:
    repo = materialise_corpus(tmp_path / "corpus")
    env = {**os.environ, **corpus_env(repo), "CI": "true"}
    process = subprocess.Popen(  # noqa: S603
        [_console_script()],
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
        yield client
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)


def test_initialize_handshake(mcp_stdio: StdioClient) -> None:
    result = mcp_stdio.handshake()["result"]
    assert result["protocolVersion"] == PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == "OpenTide"
    assert "tools" in result["capabilities"]


def test_tools_list_advertises_every_tool(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    tools = mcp_stdio.request("tools/list")["result"]["tools"]
    assert {tool["name"] for tool in tools} == EXPECTED_TOOLS


def test_search_over_stdio_returns_summary_list(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    payload = mcp_stdio.call_tool("search", {"query": CORPUS_RULE_UUIDS["sentinel"]})
    assert isinstance(payload, list)
    assert [hit["uuid"] for hit in payload] == [CORPUS_RULE_UUIDS["sentinel"]]


def test_search_platform_filter_over_stdio(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    payload = mcp_stdio.call_tool("search", {"query": "Rule", "platform": "sentinel"})
    hits = {hit["uuid"] for hit in payload}
    assert CORPUS_RULE_UUIDS["sentinel"] in hits
    assert CORPUS_RULE_UUIDS["sentinel_one"] not in hits


def test_coverage_over_stdio(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    payload = mcp_stdio.call_tool("coverage", {"technique": CORPUS_TECHNIQUE})
    assert payload["covered"] is True
    assert set(payload["rules"]) >= set(CORPUS_RULE_UUIDS.values())


def test_resources_list_and_read_platforms(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    payload = mcp_stdio.read_resource("opentide://platforms")
    capabilities = {entry["name"]: entry for entry in payload}
    assert capabilities["crowdstrike"]["can_validate"] is False
    assert capabilities["sentinel"]["can_validate"] is True


def test_resource_vocabularies_over_stdio_is_json(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    payload = mcp_stdio.read_resource("opentide://vocabularies")
    assert isinstance(payload, dict) and payload
    assert all(isinstance(entry, dict) for entry in payload.values())
    detail = mcp_stdio.read_resource(payload["actors"]["uri"])
    assert len(detail["entries"]) == payload["actors"]["entry_count"]


def test_resource_rule_body_over_stdio(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    uuid = CORPUS_RULE_UUIDS["sentinel"]
    payload = mcp_stdio.read_resource(f"opentide://rules/{uuid}")
    assert payload["metadata"]["uuid"] == uuid


def test_logs_never_bleed_onto_the_jsonrpc_stream(mcp_stdio: StdioClient) -> None:
    """Every stdout frame must parse as JSON-RPC; structlog belongs on stderr."""
    mcp_stdio.handshake()
    mcp_stdio.call_tool("validation_report", {})
    mcp_stdio.request("tools/list")
    mcp_stdio.read_resource("opentide://index")


def test_text_blocks_agree_with_structured_content(mcp_stdio: StdioClient) -> None:
    """A list-returning tool emits one text block per hit plus structuredContent."""
    mcp_stdio.handshake()
    result = mcp_stdio.raw_tool_call("search", {"query": "Rule", "platform": "sentinel"})
    blocks = [json.loads(block["text"]) for block in result["content"]]
    assert result["structuredContent"]["result"] == blocks


def test_content_length_headers_are_reported_as_protocol_errors(tmp_path: Path) -> None:
    """MCP stdio is newline-delimited: LSP-style headers are rejected frames.

    The body still parses because it is a newline-terminated JSON object, so a
    Content-Length client sees error notifications rather than silence.
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
    process = subprocess.run(  # noqa: S603
        [_console_script()],
        cwd=repo,
        env=env,
        input=framed,
        capture_output=True,
        text=True,
        timeout=READ_TIMEOUT,
    )
    frames = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    assert frames, "expected diagnostics on the NDJSON stream"
    assert all(frame["jsonrpc"] == "2.0" for frame in frames)
    errors = [
        frame
        for frame in frames
        if frame.get("method") == "notifications/message" and frame["params"]["level"] == "error"
    ]
    assert errors, "header frames should be reported as protocol errors"
    responses = [frame for frame in frames if frame.get("id") == 1]
    assert responses and responses[0]["result"]["serverInfo"]["name"] == "OpenTide"
