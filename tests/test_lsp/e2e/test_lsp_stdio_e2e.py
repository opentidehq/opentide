"""``opentide lsp start`` speaks the language server protocol on stdio (#332).

Spawns the published console script, as an editor does, and exchanges
``Content-Length`` framed JSON-RPC with it: stdout must carry nothing else.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import IO, Any

import pytest

pytestmark = pytest.mark.cli_smoke

RULE = """\
name: Suspicious Process
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
configurations:
  sentinel:
    query: |
      SecurityEvent
      | wher EventID == 4688
"""


def _server(*args: str) -> list[str]:
    candidate = Path(sys.executable).with_name("opentide")
    resolved = str(candidate) if candidate.exists() else shutil.which("opentide")
    if resolved is None:
        pytest.skip("opentide console script is not installed")
    return [resolved, "lsp", "start", *args]


def _send(stream: IO[bytes], message: dict[str, Any]) -> None:
    body = json.dumps(message).encode()
    stream.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    stream.flush()


def _read(stream: IO[bytes]) -> dict[str, Any]:
    length = None
    while True:
        line = stream.readline()
        assert line, "the server closed stdout"
        if line in (b"\r\n", b"\n"):
            break
        name, _, value = line.decode("ascii").partition(":")
        assert name.lower() == "content-length", f"not a protocol header: {line!r}"
        length = int(value)
    assert length is not None
    return json.loads(stream.read(length))


@pytest.mark.parametrize("flags", [(), ("--stdio",)], ids=["bare", "stdio-flag"])
def test_an_editor_session_from_initialize_to_exit(tmp_path: Path, flags: tuple[str, ...]) -> None:
    rule = tmp_path / "objects" / "rules" / "suspicious-process.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text(RULE, encoding="utf-8")
    process = subprocess.Popen(
        _server(*flags),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=tmp_path,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        _send(
            process.stdin,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"capabilities": {}, "rootUri": tmp_path.as_uri()},
            },
        )
        init = _read(process.stdout)
        assert init["id"] == 1
        assert init["result"]["serverInfo"]["name"] == "opentide-lsp"
        assert init["result"]["capabilities"]["hoverProvider"] is True
        _send(process.stdin, {"jsonrpc": "2.0", "method": "initialized", "params": {}})
        _send(
            process.stdin,
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": rule.as_uri(),
                        "languageId": "opentide-yaml",
                        "version": 1,
                        "text": RULE,
                    }
                },
            },
        )
        published = _read(process.stdout)
        assert published["method"] == "textDocument/publishDiagnostics"
        codes = {item["code"] for item in published["params"]["diagnostics"]}
        assert "kql_unknown_operator" in codes
        _send(process.stdin, {"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
        assert _read(process.stdout)["id"] == 2
        _send(process.stdin, {"jsonrpc": "2.0", "method": "exit"})
        process.stdin.close()
        assert process.wait(timeout=30) == 0
        assert process.stdout.read() == b"", "stdout carries the protocol and nothing else"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_closing_stdin_ends_the_server() -> None:
    process = subprocess.run(_server(), input=b"", capture_output=True, timeout=30)
    assert process.returncode == 0
    assert process.stdout == b""
