"""``opentide serve``'s Python host on the Rust engine (#822): the same answers, warm.

A run whose command the engine selection gives to Rust runs in this process
through ``opentide._native.run_cli``; the Python CLI, run fresh, is the
oracle every answer is compared with. The Rust session keeps the workspace
of a read-only run loaded for the next one.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.test_serve import (
    RULE_FILE,
    TIMEOUT,
    Client,
    StdioClient,
    _console_script,
    _stable,
    spawned_document,
)

from opentide.cli import engine_defaults
from opentide.cli.services.serve import CommandRunner
from opentide.core import progress_events


@pytest.fixture
def native() -> Iterator[ModuleType]:
    """The engine, with no warm workspace before or after the test."""
    from opentide.analysis import engine

    module = engine()
    module.clear_workspaces()
    yield module
    module.clear_workspaces()


@pytest.fixture
def rust_runs(native: ModuleType, monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """The argv of each run the engine made, as it happens."""
    seen: list[list[str]] = []
    real = native.run_cli

    def counting(argv: list[str], *args: Any) -> Any:
        seen.append(list(argv))
        return real(argv, *args)

    monkeypatch.setattr(native, "run_cli", counting)
    return seen


def _same(document: Any) -> Any:
    """*document* without its timings and clock readings (``evaluated_at``)."""
    stable = _stable(document)
    if isinstance(stable, dict):
        stable.pop("evaluated_at", None)
    return stable


def oracle(argv: list[str]) -> tuple[Any, int]:
    """What the Python CLI prints for ``opentide --json <argv>``, run fresh: the oracle."""
    return spawned_document(argv, env={"OPENTIDE_ENGINE": "python"})


def _client(tmp_path: Path) -> Client:
    env = {**os.environ, "XDG_STATE_HOME": str(tmp_path / "state")}
    elsewhere = tmp_path / "server-cwd"
    elsewhere.mkdir(exist_ok=True)
    # The Python host, whose Rust runs go through ``run_cli``: the Rust host
    # (UC-3.8) is test_serve.py's under ``rust``, and crates/opentide-cli's.
    return Client(CommandRunner(base_env=env, cwd=elsewhere), python_host=True)


@pytest.fixture
def rust_client(
    tide_corpus_repo: Path, tmp_path: Path, native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Client]:
    """A server started with ``OPENTIDE_ENGINE=rust``.

    Set in this process too: the server puts its starting environment back
    after each run.
    """
    monkeypatch.setenv("OPENTIDE_ENGINE", "rust")
    client = _client(tmp_path)
    yield client
    client.stop()


@pytest.fixture
def python_client(
    tide_corpus_repo: Path, tmp_path: Path, native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Client]:
    """A server started with no engine chosen: each command's default."""
    monkeypatch.delenv("OPENTIDE_ENGINE", raising=False)
    client = _client(tmp_path)
    yield client
    client.stop()


@pytest.mark.parametrize(
    "argv",
    [
        ["info"],
        ["info", "rules"],
        ["info", "catalog"],
        ["info", "coverage"],
        ["info", "rulez"],
        ["rules", "unreviewed"],
    ],
)
def test_a_rust_run_answers_what_python_prints(
    rust_client: Client, rust_runs: list[list[str]], argv: list[str]
) -> None:
    expected, code = oracle(argv)
    for _ in range(2):  # cold, then warm
        result = rust_client.run(*argv)
        assert result["exit_code"] == code == expected["exit_code"]
        assert _same(result["document"]) == _same(expected)
    assert rust_runs == [["--json", *argv]] * 2


def test_a_warm_run_reads_nothing_and_an_edit_is_read_without_an_invalidate(
    rust_client: Client, tide_corpus_repo: Path, native: ModuleType
) -> None:
    rust_client.run("info", "catalog")
    cold = native.workspace_stats()
    assert cold["kept"] == 1
    rust_client.run("info", "catalog")
    warm = native.workspace_stats()
    assert warm["hits"] == cold["hits"] + 1
    assert warm["file_reads"] == cold["file_reads"], "a warm run reads no object file"

    rule = tide_corpus_repo / RULE_FILE
    text = rule.read_text(encoding="utf-8")
    rule.write_text(text.replace("name: Sentinel KQL Rule", "name: Renamed Rule"), encoding="utf-8")
    edited = rust_client.run("info", "catalog")
    after = native.workspace_stats()
    assert after["refreshes"] == warm["refreshes"] + 1
    assert after["file_reads"] == warm["file_reads"] + 1, "only the edited file is read again"
    expected, _ = oracle(["info", "catalog"])
    assert "Renamed Rule" in json.dumps(edited["document"])
    assert _same(edited["document"]) == _same(expected)


def test_a_new_file_is_seen_without_an_invalidate(
    rust_client: Client, tide_corpus_repo: Path
) -> None:
    before = rust_client.run("info")["document"]["counts"]
    rule = tide_corpus_repo / RULE_FILE
    copy = rule.with_name("rule-served-copy.yaml")
    copy.write_text(
        rule.read_text(encoding="utf-8").replace(
            CORPUS_RULE_UUIDS["sentinel"], "00000000-0000-4000-8003-0000000000ee"
        ),
        encoding="utf-8",
    )
    after = rust_client.run("info")["document"]["counts"]
    expected, _ = oracle(["info"])
    assert after == expected["counts"]
    assert after != before


def test_invalidate_reaches_the_rust_session(
    rust_client: Client, tmp_path: Path, native: ModuleType
) -> None:
    rust_client.run("info")
    loaded = native.workspace_stats()["file_reads"]
    rust_client.run("info")
    assert native.workspace_stats()["file_reads"] == loaded
    # A path outside every workspace may be a file a configuration points at:
    # the workspace is loaded again, as the registry is.
    rust_client.send(
        {"method": "invalidate", "params": {"paths": [str(tmp_path / "x" / "y.yaml")]}}
    )
    rust_client.run("info")
    assert native.workspace_stats()["file_reads"] == 2 * loaded


def test_a_run_that_may_write_drops_the_warm_workspaces(
    rust_client: Client, native: ModuleType
) -> None:
    rust_client.run("info")
    assert native.workspace_stats()["kept"] == 1
    # OPENTIDE_ENGINE=python for one run: the escape hatch, per request.
    made = rust_client.run(
        "new", "threat", "--name", "Served Threat", env={"OPENTIDE_ENGINE": "python"}
    )
    assert made["exit_code"] == 0, made["document"]
    assert native.workspace_stats()["kept"] == 0
    counts = rust_client.run("info")["document"]["counts"]
    expected, _ = oracle(["info"])
    assert counts == expected["counts"]


def test_a_rust_run_that_may_write_drops_the_warm_workspaces(
    rust_client: Client, native: ModuleType, rust_runs: list[list[str]]
) -> None:
    rust_client.run("info")
    assert native.workspace_stats()["kept"] == 1
    made = rust_client.run("generate", "exports")
    assert made["exit_code"] == 0, made["document"]
    assert rust_runs == [["--json", "info"], ["--json", "generate", "exports"]]
    assert native.workspace_stats()["kept"] == 0


def test_a_rust_runs_progress_events_arrive_as_notifications(
    rust_client: Client, native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = {"event": "progress", "step": "objects", "done": 1, "total": 1}
    real = native.run_cli

    def with_events(argv: list[str], env: dict[str, str], *args: Any) -> Any:
        """The engine's contract: events on stderr when ``OPENTIDE_PROGRESS=json``."""
        code, stdout, stderr = real(argv, env, *args)
        if progress_events.requested(env):
            stderr = json.dumps(event).encode() + b"\n" + stderr
        return code, stdout, stderr

    monkeypatch.setattr(native, "run_cli", with_events)
    request_id = rust_client.request("run", {"argv": ["info"]})
    assert rust_client.answer(request_id)["result"]["exit_code"] == 0
    forwarded = [n["params"] for n in rust_client.notifications if n["method"] == "progress"]
    assert forwarded == [{"id": request_id, "event": event}]


def test_a_cancel_interrupts_the_rust_run_in_progress(
    rust_client: Client, native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    released = threading.Event()
    interrupts: list[bool] = []

    def blocking(argv: list[str], *args: Any) -> Any:
        started.set()
        # Waits in C, as the engine runs: no Python frame for a cancel to
        # raise in until the engine is interrupted and returns.
        released.wait(TIMEOUT)
        return (130, b"", b"") if released.is_set() else (0, b'{"ok": true}', b"")

    def interrupt() -> bool:
        interrupts.append(True)
        released.set()
        return True

    monkeypatch.setattr(native, "run_cli", blocking)
    monkeypatch.setattr(native, "interrupt_cli", interrupt)
    request_id = rust_client.request("run", {"argv": ["info"]})
    assert started.wait(TIMEOUT)
    rust_client.send({"method": "$/cancelRequest", "params": {"id": request_id}})
    result = rust_client.answer(request_id)["result"]
    assert interrupts == [True]
    assert result["exit_code"] == 130
    assert result["document"]["failure"]["code"] == "interrupted"
    monkeypatch.undo()
    assert rust_client.run("info")["exit_code"] == 0


def test_a_cancel_before_the_engine_returned_answers_130(
    rust_client: Client, native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def cancelled(argv: list[str], *args: Any) -> Any:
        # The KeyboardInterrupt a cancel raises, landing as the engine returns.
        raise KeyboardInterrupt

    monkeypatch.setattr(native, "run_cli", cancelled)
    outcome = rust_client.server.runner.run(["info"])
    assert outcome.exit_code == 130
    assert outcome.document["exit_code"] == 130
    assert outcome.document["failure"]["code"] == "interrupted"


def test_a_fix_runs_cold(rust_client: Client) -> None:
    runner = rust_client.server.runner
    assert runner.keeps_registry(["info", "catalog"])
    assert not runner.keeps_registry(["generate", "exports"])


def test_the_runs_environment_chooses_the_engine(
    python_client: Client, rust_runs: list[list[str]]
) -> None:
    python_client.run("info")
    assert rust_runs == []
    python_client.run("info", env={"OPENTIDE_ENGINE": "rust"})
    assert rust_runs == [["--json", "info"]]


def test_a_flipped_default_runs_rust_and_python_still_runs_python(
    python_client: Client, rust_runs: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(engine_defaults.DEFAULT_ENGINES, ("info",), "rust")
    expected, _ = oracle(["info"])
    flipped = python_client.run("info")
    assert rust_runs == [["--json", "info"]]
    hatch = python_client.run("info", env={"OPENTIDE_ENGINE": "python"})
    assert len(rust_runs) == 1
    for result in (flipped, hatch):
        assert _same(result["document"]) == _same(expected)


def test_help_and_unported_commands_go_through_python(
    rust_client: Client, rust_runs: list[list[str]]
) -> None:
    help_text = rust_client.run("info", "--help")
    assert help_text["exit_code"] == 0
    assert "Usage" in help_text["document"]["text"]
    # validate has a Rust implementation (UC-3.5); new threat has none.
    refused = rust_client.run("new", "threat")
    assert refused["exit_code"] == 2
    assert refused["document"]["failure"]["code"] == "engine_not_ported"
    assert rust_runs == []


def test_a_run_the_rust_implementation_does_not_cover_is_refused_as_at_a_terminal(
    rust_client: Client, rust_runs: list[list[str]]
) -> None:
    """``doctor`` reaches PyPI without ``--offline``: serve refuses it, as the CLI does."""
    refused = rust_client.run("doctor")
    assert refused["exit_code"] == 2
    assert refused["document"]["failure"]["code"] == "engine_not_ported"
    assert rust_runs == []
    offline = rust_client.run("doctor", "--offline")
    assert rust_runs == [["--json", "doctor", "--offline"]]
    assert offline["document"]["command"] == "doctor"


def test_a_rust_run_in_a_missing_directory_fails(rust_client: Client, tmp_path: Path) -> None:
    result = rust_client.run("info", cwd=str(tmp_path / "missing"))
    assert result["exit_code"] == 1
    assert result["document"]["failure"]["code"] == "command_failed"


def test_the_rust_runs_stderr_is_split_into_events_and_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[dict[str, Any]] = []
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)
    with progress_events.sink(events.append):
        CommandRunner._forward_stderr(
            b'{"event":"progress","step":"objects","done":1,"total":2}\n'
            b"12:00:00 debug: loaded\n"
            b'{"not":"an event"}\n'
        )
    assert events == [{"event": "progress", "step": "objects", "done": 1, "total": 2}]
    assert stderr.getvalue() == '12:00:00 debug: loaded\n{"not":"an event"}\n'


def test_nothing_to_interrupt_when_no_rust_run_is_going(native: ModuleType) -> None:
    assert native.interrupt_cli() is False
    assert CommandRunner().interrupt_rust() is False


@pytest.mark.cli_smoke
def test_over_stdio_serve_starts_under_rust_and_answers_as_python(
    tide_corpus_repo: Path, tmp_path: Path
) -> None:
    env = {**os.environ, "XDG_STATE_HOME": str(tmp_path / "state"), "OPENTIDE_ENGINE": "rust"}
    for name in ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"):
        env.pop(name, None)
    spawned = subprocess.run(
        [_console_script(), "--json", "info", "catalog"],
        cwd=tide_corpus_repo,
        env={**env, "OPENTIDE_ENGINE": "python"},
        capture_output=True,
        check=False,
    )
    expected = json.loads(spawned.stdout)
    client = StdioClient(tide_corpus_repo, env)
    try:
        for _ in range(2):
            result = client.call("run", {"argv": ["info", "catalog"]})["result"]
            assert result["exit_code"] == spawned.returncode
            assert _same(result["document"]) == _same(expected)
        client.send({"method": "exit"})
        assert client.process.wait(TIMEOUT) == 0
    finally:
        if client.process.poll() is None:
            client.process.kill()
    for line in client.stdout:
        assert json.loads(line)["jsonrpc"] == "2.0"
