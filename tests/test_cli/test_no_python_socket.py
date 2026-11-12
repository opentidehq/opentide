"""No Python code opens a socket on a command the Rust engine runs (#834).

Each run starts the CLI as ``python -m opentide`` with Python's ``socket``
module patched to refuse every connection and name lookup, so a request
made from Python fails the run. The commands that reach the network and run
on Rust (``share push``, ``share push --changed`` on a git diff, ``share
retract``, ``generate extract elastic``) are run against the stand-in
instances of ``tests/cassettes/`` on loopback: with ``OPENTIDE_ENGINE=rust``
they reach them through the Rust connectors and succeed; with
``OPENTIDE_ENGINE=python`` the same runs fail, which proves the patch bites.
``generate extract sentinel`` signs in to fixed Microsoft hosts that no
loopback stand-in can answer without intercepting TLS: its run goes to a
proxy on a closed loopback port, and fails in the Rust connector, never in a
Python socket.

The runs that still reach the network from Python, and are not covered here:
``query --rule``/``--file``, ``deploy`` and ``validate query --live`` without
``--platform``, and ``setup --skills``/``--plugin``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CASSETTES = ROOT / "tests" / "cassettes"
FIXTURES = ROOT / "tests" / "golden" / "fixtures"
#: The workspace of ``crates/opentide-cli/tests/extract_sentinel.rs``: a tenant
#: on the Sentinel stand-in.
EXTRACT_SENTINEL = ROOT / "crates" / "opentide-cli" / "tests" / "extract_sentinel"
KEY = "no-socket-test-key"

#: Runs the CLI with Python's socket module refusing every connection.
PRELUDE = """
import runpy, socket, sys

def refuse(*args, **kwargs):
    raise OSError("a Python socket was opened")

socket.socket.connect = refuse
socket.socket.connect_ex = refuse
socket.create_connection = refuse
socket.getaddrinfo = refuse
sys.argv = ["opentide", *sys.argv[1:]]
runpy.run_module("opentide", run_name="__main__")
"""


@pytest.fixture
def stand_in() -> Iterator[Callable[[str, dict[str, str]], int]]:
    """Starts a stand-in tenant of ``tests/cassettes/<name>/tenant.py``; its port."""
    started: list[subprocess.Popen[str]] = []

    def start(name: str, env: dict[str, str]) -> int:
        process = subprocess.Popen(
            [sys.executable, str(CASSETTES / name / "tenant.py")],
            stdout=subprocess.PIPE,
            text=True,
            env={**os.environ, **env},
        )
        started.append(process)
        assert process.stdout is not None
        return int(process.stdout.readline().strip())

    yield start
    for process in started:
        process.kill()
        process.wait()


#: The variables of a CI run on a GitHub push.
GITHUB_PUSH = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_SHA": "HEAD",
}


def _run(
    workspace: Path, engine: str, *args: str, extra: dict[str, str] | None = None
) -> tuple[int, dict[str, object]]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.lower().endswith("_proxy")
        and not key.startswith(("OPENTIDE_", "GITHUB_", "GITLAB_", "CI", "TF_BUILD"))
    }
    env.update(
        OPENTIDE_ENGINE=engine,
        NO_PROXY="*",
        MISP_API_KEY=KEY,
        ELASTIC_API_KEY=KEY,
        AZURE_CLIENT_SECRET=KEY,
        HOME=str(workspace.parent / "home"),
    )
    env.update(extra or {})
    done = subprocess.run(
        [sys.executable, "-c", PRELUDE, "--repo", str(workspace), "--json", *args],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return done.returncode, json.loads(done.stdout)


def _misp_workspace(tmp_path: Path, port: int) -> Path:
    workspace = tmp_path / "ws"
    shutil.copytree(FIXTURES / "share-misp", workspace)
    sharing = workspace / ".opentide" / "configurations" / "sharing.toml"
    text = sharing.read_text(encoding="utf-8")
    sharing.write_text(
        text.replace("https://misp.invalid", f"http://127.0.0.1:{port}"), encoding="utf-8"
    )
    return workspace


def _git(workspace: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            *args,
        ],
        cwd=workspace,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "opentide test",
            "GIT_AUTHOR_EMAIL": "test@opentide.invalid",
            "GIT_COMMITTER_NAME": "opentide test",
            "GIT_COMMITTER_EMAIL": "test@opentide.invalid",
        },
        check=True,
        capture_output=True,
    )


def _closed_port() -> int:
    """A loopback port nothing listens on: a connection to it is refused."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_share_push_and_retract_open_no_python_socket(
    tmp_path: Path, stand_in: Callable[[str, dict[str, str]], int]
) -> None:
    port = stand_in("misp", {"MISP_API_KEY": KEY})
    workspace = _misp_workspace(tmp_path, port)

    code, document = _run(workspace, "rust", "share", "push")
    assert code == 3, document
    actions = {(r["target"], r["object_uuid"][-2:], r["action"]) for r in document["records"]}
    assert ("misp-prod", "01", "created") in actions
    assert ("misp-prod", "12", "updated") in actions
    assert ("misp-locked", "11", "failed") in actions

    code, document = _run(
        workspace,
        "rust",
        "share",
        "retract",
        "--target",
        "misp-prod",
        "--uuid",
        "00000000-0000-4000-8048-000000000011",
    )
    assert code == 0, document
    assert [r["action"] for r in document["records"]] == ["retracted"]


def test_the_patch_refuses_a_python_run(
    tmp_path: Path, stand_in: Callable[[str, dict[str, str]], int]
) -> None:
    port = stand_in("misp", {"MISP_API_KEY": KEY})
    workspace = _misp_workspace(tmp_path, port)
    code, document = _run(workspace, "python", "share", "push", "--target", "misp-prod")
    # The objective fails its schema check before any request (exit 1).
    assert code == 1, document
    reasons = {r.get("reason") for r in document["records"] if r["action"] == "failed"}
    assert reasons == {"connectivity_failed", "validation_error"}


def test_generate_extract_elastic_opens_no_python_socket(
    tmp_path: Path, stand_in: Callable[[str, dict[str, str]], int]
) -> None:
    port = stand_in("elastic", {"ELASTIC_API_KEY": KEY})
    workspace = tmp_path / "ws"
    shutil.copytree(FIXTURES / "tenants", workspace)
    elastic = workspace / ".opentide" / "configurations" / "platforms" / "elastic.toml"
    text = elastic.read_text(encoding="utf-8")
    for host in ("https://kibana.elastic.invalid", "https://es.elastic.invalid"):
        text = text.replace(host, f"http://127.0.0.1:{port}")
    elastic.write_text(text, encoding="utf-8")

    code, document = _run(workspace, "rust", "generate", "extract", "elastic", "--space", "soc")
    assert code == 0, document
    assert document["extracted_count"] == 4
    assert len(list((workspace / "Imported").glob("*.yaml"))) == 4

    code, document = _run(workspace, "python", "generate", "extract", "elastic", "--space", "soc")
    assert code == 1, document
    assert "a Python socket was opened" in document["message"] or document["failure"]


def test_share_push_changed_reads_its_diff_and_opens_no_python_socket(
    tmp_path: Path, stand_in: Callable[[str, dict[str, str]], int]
) -> None:
    port = stand_in("misp", {"MISP_API_KEY": KEY})
    workspace = _misp_workspace(tmp_path, port)
    _git(workspace, "init", "-q")
    _git(workspace, "add", "-A")
    _git(workspace, "commit", "-q", "--no-verify", "-m", "The workspace")
    rule = workspace / "objects" / "rules" / "rule-b-update.yaml"
    text = rule.read_text(encoding="utf-8")
    rule.write_text(text.replace("stand-in receives.", "stand-in receives, pushed."), "utf-8")
    _git(workspace, "commit", "-q", "--no-verify", "-a", "-m", "A push")
    push = {**GITHUB_PUSH, "GITHUB_WORKSPACE": str(workspace)}

    code, document = _run(workspace, "rust", "share", "push", "--changed", extra=push)
    assert code == 3, document
    actions = {(r["target"], r["object_uuid"][-2:], r["action"]) for r in document["records"]}
    assert actions == {("misp-prod", "12", "updated"), ("misp-locked", "12", "failed")}

    code, document = _run(workspace, "python", "share", "push", "--changed", extra=push)
    assert code != 3, document
    reasons = {r.get("reason") for r in document["records"] if r["action"] == "failed"}
    assert "connectivity_failed" in reasons, document


def test_generate_extract_sentinel_opens_no_python_socket(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    shutil.copytree(EXTRACT_SENTINEL / "workspace", workspace)
    proxy = f"http://127.0.0.1:{_closed_port()}"
    # Every request goes to a proxy on a closed loopback port: no real host.
    through = {"HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "NO_PROXY": ""}

    code, document = _run(workspace, "rust", "generate", "extract", "sentinel", extra=through)
    assert code == 1, document
    assert "a Python socket was opened" not in json.dumps(document)
    assert document["command"] == "generate extract sentinel"
    assert not (workspace / "Imported").exists()

    code, document = _run(workspace, "python", "generate", "extract", "sentinel", extra=through)
    assert code == 1, document
    assert "a Python socket was opened" in json.dumps(document), document
