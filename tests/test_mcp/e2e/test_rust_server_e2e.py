"""``OPENTIDE_ENGINE=rust opentide mcp start`` over stdio (UC-3.7, #829).

The Rust server (rmcp) runs in the package's Python process and hands the
tools it has no implementation of to the Python handlers there. These run it
as a client does and hold what the recorded sessions cannot: stdout carries
JSON-RPC alone whatever else in the process writes to it, and the root
options reach the Python half.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, materialise_corpus

from .test_mcp_stdio_e2e import StdioClient

pytestmark = pytest.mark.cli_smoke

#: The process ``mcp start`` runs under ``rust`` (``python -m opentide.cli.rust``),
#: whose delegated handlers write to descriptor 1 three ways: the descriptor
#: itself, ``print``, and a child process that inherits it.
NOISY_SERVER = """
import os, subprocess, sys
import opentide.mcp_server.bridge as bridge

original = bridge.call_tool

def noisy(name, arguments):
    os.write(1, b"stray-descriptor\\n")
    print("stray-print", flush=True)
    subprocess.run([sys.executable, "-c", "print('stray-child')"], check=True)
    return original(name, arguments)

bridge.call_tool = noisy
sys.argv = ["opentide", *sys.argv[1:]]
from opentide.cli.rust import main
raise SystemExit(main())
"""


def _environment(**extra: str) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE", "CLAUDE_PROJECT_DIR"}
    }
    env.update({"CI": "true", **extra})
    return env


def _start(argv: list[str], cwd: Path, env: dict[str, str]) -> StdioClient:
    process = subprocess.Popen(
        [sys.executable, *argv],
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    return StdioClient(process)


def test_stray_output_in_the_process_never_reaches_the_frames(tmp_path: Path) -> None:
    repo = materialise_corpus(tmp_path / "corpus")
    client = _start(
        ["-c", NOISY_SERVER, "mcp", "start"],
        repo,
        _environment(
            OPENTIDE_ENGINE="rust", OPENTIDE_REPO_ROOT=str(repo), OPENTIDE_TIDE_WORKSPACE=str(repo)
        ),
    )
    client.handshake()
    hits = client.call_tool("search", {"query": CORPUS_RULE_UUIDS["sentinel"]})
    assert [hit["uuid"] for hit in hits] == [CORPUS_RULE_UUIDS["sentinel"]]
    report = client.call_tool("validation_report", {})
    assert "next_actions" in report
    lines = client.close_and_drain()
    for line in lines:
        if line.strip():
            assert json.loads(line)["jsonrpc"] == "2.0", line
    for stray in ("stray-descriptor", "stray-print", "stray-child"):
        assert stray in client.stderr, client.stderr


@pytest.mark.parametrize("engine", ["python", "rust"])
def test_repo_names_the_workspace_from_outside_it(tmp_path: Path, engine: str) -> None:
    """``opentide --repo <ws> mcp start`` from another folder serves ``<ws>`` to every tool."""
    repo = materialise_corpus(tmp_path / "corpus")
    outside = tmp_path / "outside"
    outside.mkdir()
    client = _start(
        ["-m", "opentide", "--repo", str(repo), "mcp", "start"],
        outside,
        _environment(OPENTIDE_ENGINE=engine),
    )
    client.handshake()
    hits = client.call_tool("search", {"query": "Rule", "platform": "sentinel"})
    assert CORPUS_RULE_UUIDS["sentinel"] in {hit["uuid"] for hit in hits}, hits
    report = client.call_tool(
        "validation_report", {"file": "objects/rules/rule-0001-sentinel-kql.yaml"}
    )
    assert report["ok"] is True, report
    assert report["stats"]["objects_checked"] == 1, report
    rules = client.read_resource("opentide://rules")
    assert CORPUS_RULE_UUIDS["sentinel"] in json.dumps(rules)
    client.close_and_drain()
