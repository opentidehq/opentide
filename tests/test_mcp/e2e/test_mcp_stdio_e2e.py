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

import opentide

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


@pytest.fixture
def mcp_stdio(tmp_path: Path) -> Iterator[StdioClient]:
    repo = materialise_corpus(tmp_path / "corpus")
    env = {**os.environ, **corpus_env(repo), "CI": "true"}
    process = subprocess.Popen(
        _server_argv(),
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
    assert result["serverInfo"]["name"] == "opentide"
    # mcp 2.x reports "" unless the server passes version= explicitly.
    assert result["serverInfo"]["version"] == opentide.__version__
    assert "tools" in result["capabilities"]


def test_server_info_reports_the_opentide_version(mcp_stdio: StdioClient) -> None:
    """It reported the MCP SDK's version (1.30.0) as its own (post-merge end-to-end run)."""
    from opentide import __version__

    result = mcp_stdio.handshake()["result"]
    assert result["serverInfo"]["version"] == __version__


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


def test_every_advertised_vocabulary_uri_is_readable(mcp_stdio: StdioClient) -> None:
    """The index's ``uri`` values must resolve, ``att&ck`` included.

    mcp 2.x matches ``{name}`` as an RFC 6570 simple expansion, which does not
    admit a literal ``&``: ``opentide://vocabularies/att&ck`` was "Unknown
    resource" even though the index advertises it.
    """
    mcp_stdio.handshake()
    index = mcp_stdio.read_resource("opentide://vocabularies")
    assert "att&ck" in index
    unreadable = {}
    for name, entry in index.items():
        response = mcp_stdio.request("resources/read", {"uri": entry["uri"]})
        if "error" in response:
            unreadable[name] = response["error"]["message"]
            continue
        detail = json.loads(response["result"]["contents"][0]["text"])
        assert "error" not in detail, (name, detail)
    assert not unreadable, unreadable
    # A client that percent-encodes the name per RFC 6570 reaches it too.
    encoded = mcp_stdio.read_resource("opentide://vocabularies/att%26ck")
    assert "error" not in encoded


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


def test_stdout_holds_only_jsonrpc_while_tools_run(mcp_stdio: StdioClient) -> None:
    """``mcp start`` runs in ``mcp`` mode: every byte on stdout is a JSON-RPC frame.

    ``validate_query`` drives the CLI's query service with a non-JSON context,
    the path most likely to print a human line. Everything the server writes
    until it exits is read back, not only the frames a request waited for.
    """
    mcp_stdio.handshake()
    payload = mcp_stdio.call_tool(
        "validate_query", {"query": "SecurityEvent", "platform": "sentinel", "live": True}
    )
    assert isinstance(payload, dict)
    assert "_failure_code" not in payload
    mcp_stdio.call_tool("validation_report", {})
    mcp_stdio.call_tool("explain", {"code": "vocab_unknown"})
    for line in mcp_stdio.close_and_drain():
        if line.strip():
            assert json.loads(line)["jsonrpc"] == "2.0", line


def test_initialize_carries_the_tagline_and_workflow(mcp_stdio: StdioClient) -> None:
    instructions = mcp_stdio.handshake()["result"]["instructions"]
    assert instructions.startswith(
        "opentide: Spec-driven development for agentic detection engineering."
    )
    assert "validation_report" in instructions
    assert "dry_run true" in instructions


def test_every_tool_describes_itself(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    tools = mcp_stdio.request("tools/list")["result"]["tools"]
    for tool in tools:
        assert len(tool["description"].split()) >= 8, tool["name"]


def test_explain_over_stdio(mcp_stdio: StdioClient) -> None:
    mcp_stdio.handshake()
    page = mcp_stdio.call_tool("explain", {"code": "invalid_ref"})
    assert page["found"] is True
    assert page["code"] == "invalid_ref"
    assert page["markdown"].startswith("# invalid_ref")
    listing = mcp_stdio.call_tool("explain", {})
    assert "invalid_ref" in {entry["code"] for entry in listing["codes"]}


def test_validation_report_over_stdio_carries_diagnostic_fields(tmp_path: Path) -> None:
    """A typo on disk comes back with its position, a fix and next actions."""
    repo = materialise_corpus(tmp_path / "corpus")
    rule = repo / "objects" / "rules" / "rule-0001-sentinel-kql.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("  tlp: clear\n", "  tlp: clearr\n", 1),
        encoding="utf-8",
    )
    env = {**os.environ, **corpus_env(repo), "CI": "true"}
    process = subprocess.Popen(
        _server_argv(),
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
        client.handshake()
        report = client.call_tool(
            "validation_report", {"file": "objects/rules/rule-0001-sentinel-kql.yaml"}
        )
        issue = next(item for item in report["issues"] if item["code"] == "vocab_unknown")
        assert issue["line"] == issue["yaml_line"] + 1
        assert issue["fix"]["safe"] is False
        assert issue["fix"]["edits"][0]["replacement"] == "clear"
        assert issue["explain"] == "opentide explain vocab_unknown"
        assert report["next_actions"][0]["tool"] == "explain"
        for line in client.close_and_drain():
            if line.strip():
                assert json.loads(line)["jsonrpc"] == "2.0", line
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=15)


def test_text_blocks_agree_with_structured_content(mcp_stdio: StdioClient) -> None:
    """A list-returning tool emits one text block per hit plus structuredContent."""
    mcp_stdio.handshake()
    result = mcp_stdio.raw_tool_call("search", {"query": "Rule", "platform": "sentinel"})
    blocks = [json.loads(block["text"]) for block in result["content"]]
    assert result["structuredContent"]["result"] == blocks


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
