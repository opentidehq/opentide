"""``opentide serve``: CLI commands in one warm process, over newline-delimited JSON-RPC (#750).

Most tests drive :class:`opentide.cli.services.serve.Server` in this process,
feeding it lines as the reading thread does and reading what it writes. The
last ones spawn the console script and speak the protocol over its stdio.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, clear_runtime_caches, materialise_corpus
from typer.testing import CliRunner

from opentide import __version__
from opentide.cli import app
from opentide.cli.services import serve as serve_mod
from opentide.cli.services.serve import CommandRunner, Server, commands_digest

RULE_FILE = "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"
#: How long a test waits for an answer before it fails.
TIMEOUT = 120.0


#: Wall-clock times, which differ between any two runs of the same command.
_TIMINGS = frozenset({"duration_ms", "wall_ms", "elapsed_ms", "seconds"})


def _stable(document: Any) -> Any:
    """*document* without what differs between two runs of the same command: its timings."""
    if isinstance(document, dict):
        return {key: _stable(value) for key, value in document.items() if key not in _TIMINGS}
    if isinstance(document, list):
        return [_stable(value) for value in document]
    return document


def spawned_document(argv: list[str], *, env: dict[str, str] | None = None) -> tuple[Any, int]:
    """What ``opentide --json <argv>`` prints in this process, as a fresh run."""
    clear_runtime_caches()
    result = CliRunner().invoke(app, ["--json", *argv], env=env)
    clear_runtime_caches()
    return json.loads(result.stdout), result.exit_code


class Client:
    """A client of an in-process :class:`Server`, with its loop on a thread."""

    def __init__(self, runner: CommandRunner) -> None:
        self.messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self.notifications: list[dict[str, Any]] = []
        self.server = Server(self._received, runner=runner)
        self.code: int | None = None
        self._next = 0
        self._loop = threading.Thread(target=self._serve, daemon=True)
        self._loop.start()

    def _serve(self) -> None:
        self.code = self.server.serve()

    def _received(self, message: dict[str, Any]) -> None:
        assert message["jsonrpc"] == "2.0"
        # Each message must survive the newline-delimited framing.
        line = json.dumps(message)
        assert "\n" not in line
        self.messages.put(json.loads(line))

    def send(self, message: dict[str, Any] | str) -> None:
        line = message if isinstance(message, str) else json.dumps({"jsonrpc": "2.0", **message})
        self.server.receive(line.encode("utf-8"))

    def request(self, method: str, params: Any = None) -> int:
        self._next += 1
        message: dict[str, Any] = {"id": self._next, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        return self._next

    def answer(self, request_id: Any) -> dict[str, Any]:
        deadline = time.monotonic() + TIMEOUT
        while True:
            message = self.messages.get(timeout=max(0.1, deadline - time.monotonic()))
            if "method" in message:
                self.notifications.append(message)
                continue
            if message.get("id") == request_id:
                return message
            raise AssertionError(f"unexpected answer {message}")

    def call(self, method: str, params: Any = None) -> dict[str, Any]:
        return self.answer(self.request(method, params))

    def run(self, *argv: str, **params: Any) -> dict[str, Any]:
        answer = self.call("run", {"argv": list(argv), **params})
        assert "result" in answer, answer
        return answer["result"]

    def stop(self) -> int | None:
        self.send({"method": "exit"})
        self._loop.join(TIMEOUT)
        return self.code


@pytest.fixture
def client(tide_corpus_repo: Path, tmp_path: Path) -> Iterator[Client]:
    env = {**os.environ, "XDG_STATE_HOME": str(tmp_path / "state")}
    elsewhere = tmp_path / "server-cwd"
    elsewhere.mkdir()
    client = Client(CommandRunner(base_env=env, cwd=elsewhere))
    yield client
    client.stop()
    clear_runtime_caches()


# --- the protocol ----------------------------------------------------------------------


def test_initialize_names_the_protocol_version_and_command_tree(client: Client) -> None:
    result = client.call("initialize", {})["result"]
    tree, code = spawned_document(["commands"])
    assert code == 0
    assert result == {
        "protocol": 1,
        "version": __version__,
        "commands_digest": commands_digest(tree),
    }
    assert "serve" in [command["path"] for command in tree["commands"]]


def test_the_digest_ignores_the_duration() -> None:
    assert commands_digest({"a": 1, "duration_ms": 3}) == commands_digest(
        {"duration_ms": 9, "a": 1}
    )
    assert commands_digest({"a": 1}) != commands_digest({"a": 2})


def test_protocol_problems_are_json_rpc_errors(client: Client) -> None:
    client.send("{not json")
    assert client.messages.get(timeout=TIMEOUT)["error"]["code"] == -32700
    client.send("[]")
    assert client.messages.get(timeout=TIMEOUT)["error"]["code"] == -32600
    client.send({"id": 1})
    assert client.messages.get(timeout=TIMEOUT)["error"]["code"] == -32600
    assert client.call("nope")["error"]["code"] == -32601
    for params in (
        None,
        {},
        {"argv": []},
        {"argv": "validate"},
        {"argv": [1]},
        {"argv": ["--json"]},
    ):
        assert client.call("run", params)["error"]["code"] == -32602, params
    assert client.call("run", {"argv": ["info"], "env": {"A": 1}})["error"]["code"] == -32602
    client.send({"method": "unknown/notification"})  # ignored
    assert client.run("explain", "vocab_unknown")["exit_code"] == 0


def test_shutdown_then_exit_ends_the_loop_with_zero(client: Client) -> None:
    assert client.call("shutdown")["result"] is None
    assert client.call("run", {"argv": ["info"]})["error"]["code"] == -32600
    assert client.stop() == 0


# --- run -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["validate", "--file", RULE_FILE],
        ["info"],
        ["lint"],
        ["explain", "vocab_unknown"],
        ["info", "rulez"],
        ["validate", "--type", "rulez"],
        ["bogus"],
    ],
)
def test_a_run_answers_what_the_command_prints(client: Client, argv: list[str]) -> None:
    expected, code = spawned_document(argv)
    for _ in range(2):  # cold, then warm
        result = client.run(*argv)
        assert result["exit_code"] == code == expected["exit_code"]
        assert _stable(result["document"]) == _stable(expected)


def test_a_command_failure_is_a_result_not_an_error(client: Client) -> None:
    result = client.run("info", "rulez")
    assert result["exit_code"] == 2
    assert result["document"]["failure"]["code"] == "usage_invalid_choice"


def test_a_command_that_would_prompt_needs_input(client: Client) -> None:
    result = client.run("setup")
    assert result["exit_code"] == 2
    assert result["document"]["failure"]["code"] == "usage_needs_input"


def test_protocol_commands_are_refused(client: Client) -> None:
    for argv in (["serve"], ["mcp", "start"], ["lsp", "start"], ["tui"]):
        result = client.run(*argv)
        assert result["exit_code"] == 2, argv
        assert result["document"]["failure"]["code"] == "usage_error"


def test_help_text_comes_back_as_text(client: Client) -> None:
    result = client.run("validate", "--help")
    assert result["exit_code"] == 0
    assert "Usage" in result["document"]["text"]


def test_each_run_resolves_its_own_workspace(
    client: Client, tide_corpus_repo: Path, tmp_path: Path
) -> None:
    """--repo, then OPENTIDE_REPO_ROOT from env, then the server's own.

    ``cwd`` is checked over stdio: the suite pins workspace discovery from the
    working directory in this process (``tests/conftest.py``).
    """
    other = materialise_corpus(tmp_path / "other")
    first = client.run("info")["document"]
    by_repo = client.run("--repo", str(other), "info")["document"]
    by_env = client.run("info", env={"OPENTIDE_REPO_ROOT": str(other)})["document"]
    assert first["repo"] == str(tide_corpus_repo)
    assert [by_repo["repo"], by_env["repo"]] == [str(other)] * 2
    assert client.run("--repo", str(other), "info", env={"OPENTIDE_REPO_ROOT": "/nowhere"})[
        "document"
    ]["repo"] == str(other)
    # The server's own state is put back after every run.
    assert os.environ.get("OPENTIDE_REPO_ROOT") == str(tide_corpus_repo)
    assert client.run("info")["document"]["repo"] == str(tide_corpus_repo)
    assert Path.cwd() == client.server.runner.cwd


def test_progress_events_arrive_as_notifications(client: Client) -> None:
    request_id = client.request("run", {"argv": ["validate"]})
    answer = client.answer(request_id)
    assert answer["result"]["exit_code"] in (0, 1)
    events = [n["params"] for n in client.notifications if n["method"] == "progress"]
    assert events and all(event["id"] == request_id for event in events)
    objects = [e["event"] for e in events if e["event"]["step"] == "objects"]
    assert objects[-1]["done"] == objects[-1]["total"]


# --- caching ---------------------------------------------------------------------------


@pytest.fixture
def builds(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Each registry build, as it happens."""
    from opentide.core import index_manager

    built: list[float] = []
    real = index_manager.build_registry

    def counting() -> Any:
        built.append(time.monotonic())
        return real()

    monkeypatch.setattr(index_manager, "build_registry", counting)
    return built


def test_a_repeat_run_keeps_the_registry_and_invalidate_drops_it(
    client: Client, tide_corpus_repo: Path, builds: list[float]
) -> None:
    rule = tide_corpus_repo / RULE_FILE
    assert client.run("validate", "--file", RULE_FILE)["exit_code"] == 0
    assert client.run("validate", "--file", RULE_FILE)["exit_code"] == 0
    assert client.run("info")["exit_code"] == 0
    assert len(builds) == 1

    # An edit: the rule's name is no longer a string. Until invalidate, the kept
    # registry still holds the old rule; after it, the next run reads the edit.
    text = rule.read_text(encoding="utf-8")
    rule.write_text(text.replace("name: Sentinel KQL Rule", "name: [1, 2]"), encoding="utf-8")
    client.send({"method": "invalidate", "params": {"paths": [str(rule)]}})
    edited = client.run("validate", "--file", RULE_FILE)
    assert edited["exit_code"] == 1, edited["document"]["report"]
    assert len(builds) == 2
    expected, code = spawned_document(["validate", "--file", RULE_FILE])
    assert code == 1
    assert _stable(edited["document"]) == _stable(expected)


def test_an_edit_on_disk_is_read_without_an_invalidate(
    client: Client, tide_corpus_repo: Path, builds: list[float]
) -> None:
    # The editor's invalidate for a save can reach the server after the run
    # that the save started: the kept registry must not answer for the old file.
    rule = tide_corpus_repo / RULE_FILE
    assert client.run("validate", "--file", RULE_FILE)["exit_code"] == 0
    text = rule.read_text(encoding="utf-8")
    rule.write_text(text.replace("name: Sentinel KQL Rule", "name: [1, 2]"), encoding="utf-8")
    edited = client.run("validate", "--file", RULE_FILE)
    assert len(builds) == 2
    expected, code = spawned_document(["validate", "--file", RULE_FILE])
    assert code == 1
    assert edited["exit_code"] == 1, edited["document"]["report"]
    assert _stable(edited["document"]) == _stable(expected)


def test_a_file_created_after_a_run_is_seen_without_an_invalidate(
    client: Client, tide_corpus_repo: Path, builds: list[float]
) -> None:
    before = client.run("info")["document"]["counts"]
    rule = tide_corpus_repo / RULE_FILE
    copy = rule.with_name("rule-served-copy.yaml")
    text = rule.read_text(encoding="utf-8")
    copy.write_text(
        text.replace(CORPUS_RULE_UUIDS["sentinel"], "00000000-0000-4000-8003-0000000000ee"),
        encoding="utf-8",
    )
    after = client.run("info")["document"]["counts"]
    # Unchanged files: the next run reuses what the last one built.
    client.run("info")
    assert len(builds) == 2
    expected, _ = spawned_document(["info"])
    assert after == expected["counts"]
    assert after != before


def test_invalidate_outside_every_workspace_drops_everything(
    client: Client, tmp_path: Path, builds: list[float]
) -> None:
    client.run("info")
    client.send({"method": "invalidate", "params": {"paths": [str(tmp_path / "x" / "y.yaml")]}})
    client.run("info")
    assert len(builds) == 2


def test_a_command_that_writes_keeps_nothing(
    client: Client, tide_corpus_repo: Path, builds: list[float]
) -> None:
    client.run("info")
    client.run("info")
    assert len(builds) == 1
    result = client.run("new", "threat", "--name", "Served Threat")
    assert result["exit_code"] == 0, result["document"]
    after_new = len(builds)
    counts = client.run("info")["document"]["counts"]
    # The read after the write built the registry again, and sees the new threat.
    assert len(builds) == after_new + 1
    expected, _ = spawned_document(["info"])
    assert counts == expected["counts"]


def test_a_fix_is_not_read_only(client: Client) -> None:
    runner = client.server.runner
    assert runner.keeps_registry(["validate", "--file", "x"])
    assert runner.keeps_registry(["--repo", "r", "lint"])
    assert not runner.keeps_registry(["validate", "--fix"])
    assert not runner.keeps_registry(["lint", "--fix"])
    assert not runner.keeps_registry(["generate"])
    assert not runner.keeps_registry(["deploy", "--dry-run"])


# --- cancel and crash ------------------------------------------------------------------


def test_cancel_stops_the_run_with_130_and_cleanup_runs(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    cleaned = threading.Event()

    def forever(*args: Any, **kwargs: Any) -> Any:
        started.set()
        try:
            while True:
                time.sleep(0.01)
        finally:
            cleaned.set()

    monkeypatch.setattr("opentide.cli.services.validation.run_validate", forever)
    request_id = client.request("run", {"argv": ["validate"]})
    assert started.wait(TIMEOUT)
    client.send({"method": "$/cancelRequest", "params": {"id": request_id}})
    result = client.answer(request_id)["result"]
    assert cleaned.is_set()
    assert result["exit_code"] == 130
    assert result["document"]["exit_code"] == 130
    assert result["document"]["failure"]["code"] == "interrupted"
    monkeypatch.undo()
    assert client.run("explain", "vocab_unknown")["exit_code"] == 0


def test_cancelling_a_queued_run_answers_130_without_running_it(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()
    started = threading.Event()
    calls: list[str] = []

    def slow(*args: Any, **kwargs: Any) -> Any:
        calls.append("run")
        started.set()
        release.wait(TIMEOUT)
        raise SystemExit(0)

    monkeypatch.setattr("opentide.cli.services.validation.run_validate", slow)
    first = client.request("run", {"argv": ["validate"]})
    assert started.wait(TIMEOUT)
    second = client.request("run", {"argv": ["validate"]})
    client.send({"method": "$/cancelRequest", "params": {"id": second}})
    release.set()
    assert client.answer(first)["result"]["exit_code"] == 0
    assert client.answer(second)["result"]["exit_code"] == 130
    assert calls == ["run"]


def test_a_cancel_after_the_command_returned_keeps_its_answer(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The cancel lands while the run parses what the command printed: the
    # command has finished, so its own document and exit code come back.
    parsing = threading.Event()
    release = threading.Event()
    real = CommandRunner._document

    def slow_document(self: CommandRunner, *args: Any) -> Any:
        parsing.set()
        while not release.is_set():
            time.sleep(0.01)
        return real(self, *args)

    monkeypatch.setattr(CommandRunner, "_document", slow_document)
    request_id = client.request("run", {"argv": ["explain", "vocab_unknown"]})
    assert parsing.wait(TIMEOUT)
    client.send({"method": "$/cancelRequest", "params": {"id": request_id}})
    release.set()
    result = client.answer(request_id)["result"]
    assert result["exit_code"] == 0, result
    assert result["document"]["command"] == "explain"
    assert "failure" not in result["document"] or not result["document"]["failure"]


def test_a_cancelled_run_names_its_command(client: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    # Cancelled before the run thread started: the fallback document still
    # carries the command.
    def cancelled_work(self: Server, work: Any, *, job: Any = None, argv: Any = ()) -> Any:
        assert job is not None
        job.cancelled = True
        return real(self, work, job=job, argv=argv)

    real = Server._on_thread
    monkeypatch.setattr(Server, "_on_thread", cancelled_work)
    result = client.run("explain", "vocab_unknown")
    assert result["exit_code"] == 130
    assert result["document"]["command"] == "explain"


class RecordingRunner(CommandRunner):
    """A runner that records each run instead of running it."""

    def __init__(self) -> None:
        super().__init__(base_env={}, cwd=Path.cwd())
        self.calls: list[list[str]] = []

    def run(self, argv: Any, *, cwd: str | None = None, env: Any = None, **_: Any) -> Any:
        self.calls.append(list(argv))
        return serve_mod.RunOutcome({"ok": True}, 0)


@pytest.mark.parametrize("ending", ["close_input", "exit"])
def test_queued_runs_do_not_run_after_exit_or_the_end_of_input(ending: str) -> None:
    written: list[dict[str, Any]] = []
    runner = RecordingRunner()
    server = Server(written.append, runner=runner)
    for request_id in (1, 2, 3):
        message = {"jsonrpc": "2.0", "id": request_id, "method": "run"}
        message["params"] = {"argv": ["deploy", "--strategy", "PRODUCTION"]}
        server.receive(json.dumps(message))
    if ending == "exit":
        server.receive(json.dumps({"jsonrpc": "2.0", "method": "exit"}))
    else:
        server.close_input()
    assert server.serve() == 0
    assert runner.calls == []
    answers = {message["id"]: message["result"]["exit_code"] for message in written}
    assert answers == {1: 130, 2: 130, 3: 130}


def test_a_client_that_disconnects_ends_the_session_with_zero() -> None:
    writes: list[dict[str, Any]] = []

    def write(message: dict[str, Any]) -> None:
        if writes:
            raise BrokenPipeError(32, "Broken pipe")
        writes.append(message)

    runner = RecordingRunner()
    server = Server(write, runner=runner)
    for request_id in (1, 2, 3):
        message = {"jsonrpc": "2.0", "id": request_id, "method": "run"}
        message["params"] = {"argv": ["validate"]}
        server.receive(json.dumps(message))
    # No exit and no end of input: the failed write alone ends the session.
    assert server.serve() == 0
    assert [message["id"] for message in writes] == [1]
    # The run whose answer could not be written was the last one to run.
    assert runner.calls == [["validate"], ["validate"]]


def test_a_cancel_for_a_finished_run_changes_nothing(client: Client) -> None:
    request_id = client.request("run", {"argv": ["explain", "vocab_unknown"]})
    assert client.answer(request_id)["result"]["exit_code"] == 0
    client.send({"method": "$/cancelRequest", "params": {"id": request_id}})
    assert client.run("explain", "vocab_unknown")["exit_code"] == 0


def test_a_crash_answers_internal_and_the_server_keeps_serving(
    client: Client, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def explode(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("index exploded")

    monkeypatch.setattr("opentide.cli.services.validation.run_validate", explode)
    result = client.run("validate")
    assert result["exit_code"] == 1
    failure = result["document"]["failure"]
    assert failure["code"] == "internal"
    assert failure["message"] == "RuntimeError: index exploded"
    assert failure["crash_log"] and Path(failure["crash_log"]).is_relative_to(tmp_path)
    monkeypatch.undo()
    assert client.run("validate", "--file", RULE_FILE)["exit_code"] == 0


def test_a_run_in_a_missing_directory_fails(client: Client, tmp_path: Path) -> None:
    result = client.run("info", cwd=str(tmp_path / "missing"))
    assert result["exit_code"] == 1
    assert result["document"]["failure"]["code"] == "command_failed"


def test_requests_are_answered_in_order(client: Client) -> None:
    ids = [client.request("run", {"argv": ["explain", "vocab_unknown"]}) for _ in range(3)]
    answers = []
    while len(answers) < 3:
        message = client.messages.get(timeout=TIMEOUT)
        if "id" in message:
            answers.append(message["id"])
    assert answers == ids


def test_raising_in_a_thread_targets_that_thread_only() -> None:
    caught = threading.Event()
    waiting = threading.Event()

    def target() -> None:
        try:
            waiting.set()
            while True:
                time.sleep(0.01)
        except KeyboardInterrupt:
            caught.set()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    assert waiting.wait(TIMEOUT)
    assert thread.ident is not None
    serve_mod._raise_in_thread(thread.ident, KeyboardInterrupt)
    thread.join(TIMEOUT)
    assert caught.is_set()


# --- over stdio ------------------------------------------------------------------------


def _console_script() -> str:
    found = shutil.which("opentide", path=str(Path(sys.executable).parent))
    assert found, "the opentide console script is not installed next to this interpreter"
    return found


class StdioClient:
    """``opentide serve`` as a child process."""

    def __init__(self, cwd: Path, env: dict[str, str]) -> None:
        self.process = subprocess.Popen(
            [_console_script(), "serve"],
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.lines: queue.Queue[bytes] = queue.Queue()
        self.stdout: list[bytes] = []
        threading.Thread(target=self._pump, daemon=True).start()
        self._next = 0

    def _pump(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.stdout.append(line)
            self.lines.put(line)

    def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((json.dumps({"jsonrpc": "2.0", **message}) + "\n").encode())
        self.process.stdin.flush()

    def call(self, method: str, params: Any = None) -> dict[str, Any]:
        self._next += 1
        self.send({"id": self._next, "method": method, "params": params or {}})
        while True:
            message = json.loads(self.lines.get(timeout=TIMEOUT))
            if message.get("id") == self._next:
                return message


@pytest.fixture
def stdio_env(tide_corpus_repo: Path, tmp_path: Path) -> dict[str, str]:
    env = {**os.environ, "XDG_STATE_HOME": str(tmp_path / "state")}
    for name in ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"):
        env.pop(name, None)
    return env


@pytest.mark.cli_smoke
def test_over_stdio_a_run_matches_the_spawned_command_and_is_faster(
    tide_corpus_repo: Path, stdio_env: dict[str, str], tmp_path: Path
) -> None:
    other = materialise_corpus(tmp_path / "other")
    argv = ["validate", "--file", RULE_FILE]
    began = time.perf_counter()
    spawned = subprocess.run(
        [_console_script(), "--json", *argv],
        cwd=tide_corpus_repo,
        env=stdio_env,
        capture_output=True,
        check=False,
    )
    spawn_seconds = time.perf_counter() - began
    expected = json.loads(spawned.stdout)

    client = StdioClient(tide_corpus_repo, stdio_env)
    try:
        init = client.call("initialize")["result"]
        assert init["protocol"] == 1 and init["version"] == __version__
        first = client.call("run", {"argv": argv})["result"]
        began = time.perf_counter()
        repeat = client.call("run", {"argv": argv})["result"]
        repeat_seconds = time.perf_counter() - began
        for result in (first, repeat):
            assert result["exit_code"] == spawned.returncode
            assert _stable(result["document"]) == _stable(expected)
        assert repeat_seconds < spawn_seconds, (repeat_seconds, spawn_seconds)

        # A run names another workspace with cwd, which wins over OPENTIDE_REPO_ROOT.
        for params in ({}, {"env": {"OPENTIDE_REPO_ROOT": str(tide_corpus_repo)}}):
            elsewhere = client.call("run", {"argv": ["info"], "cwd": str(other), **params})
            assert elsewhere["result"]["document"]["repo"] == str(other), params
        here = client.call("run", {"argv": ["info"]})["result"]
        assert here["document"]["repo"] == str(tide_corpus_repo)

        assert client.call("shutdown")["result"] is None
        client.send({"method": "exit"})
        assert client.process.wait(TIMEOUT) == 0
    finally:
        if client.process.poll() is None:
            client.process.kill()
    # stdout carried JSON-RPC and nothing else, one message a line.
    for line in client.stdout:
        assert json.loads(line)["jsonrpc"] == "2.0"


@pytest.mark.cli_smoke
def test_over_stdio_closing_stdin_ends_the_server(
    tide_corpus_repo: Path, stdio_env: dict[str, str]
) -> None:
    client = StdioClient(tide_corpus_repo, stdio_env)
    assert client.call("run", {"argv": ["explain", "vocab_unknown"]})["result"]["exit_code"] == 0
    assert client.process.stdin is not None
    client.process.stdin.close()
    assert client.process.wait(TIMEOUT) == 0


def test_serve_is_listed_with_no_document(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(app, ["--json", "commands"])
    tree = json.loads(result.stdout)
    entry = next(command for command in tree["commands"] if command["path"] == "serve")
    assert entry["output_schema"] is None


def test_the_corpus_rule_is_the_sentinel_one() -> None:
    assert CORPUS_RULE_UUIDS["sentinel"] in (
        Path(__file__).resolve().parents[1] / "fixtures/tide_corpus/current" / RULE_FILE
    ).read_text(encoding="utf-8")
