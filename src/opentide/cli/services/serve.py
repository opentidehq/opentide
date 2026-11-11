"""``opentide serve``: run CLI commands in one warm process, for editors.

JSON-RPC 2.0, one message per line, on stdin and stdout (the contract is in
``docs/cli/serve.md``). Each ``run`` executes a command in this process, as
``opentide --json <argv>`` would in a new one, and answers with the document
that command prints and its exit code. The imports, the loaded command
modules and, for the commands that only read the workspace, the registry
stay warm between runs: a repeat ``validate --file`` skips Python start-up and
the rebuild of the index from every YAML file.

How a run stays the same as a spawned command:

- **Its own process state.** Before each run the environment is reset to the
  one the server started with, plus the run's ``env``, the working directory
  is the run's ``cwd``, and the caches a command run fills (the repository
  root, the schema pipeline's bindings, the platform registry) are dropped.
  Afterwards both are put back.
- **Its own stdout.** The command writes into a buffer, which is parsed into
  the ``document``. The protocol has the real stdout to itself.
- **Its own thread.** Click keeps its context per thread. A cancel raises
  ``KeyboardInterrupt`` in that thread, so ``finally`` blocks and context
  managers run (a CrowdStrike search is stopped), and the command exits 130
  as it does on Ctrl-C.

Requests are handled one at a time, in the order they arrive. ``$/cancelRequest``
acts at once; ``invalidate`` is queued with the requests, so it takes effect
after the running command and before the next one.

**The Rust engine (#822).** A run whose command the engine selection
(``OPENTIDE_ENGINE`` in the server's or the run's environment, else the
command's default, :mod:`opentide.cli.engine_defaults`) gives to its Rust
implementation runs that implementation in this process
(``opentide._native.run_cli``), with the run's environment and working
directory, and answers with the document it prints. A read-only run keeps
its workspace loaded in the Rust session for the next one
(``opentide-workspace``'s ``session``): it is brought up to date at each run
(an edit on disk is read without an ``invalidate``, and only the files that
changed are read again), ``invalidate`` reaches it, and a run that may
write drops it, as for the registry. Its progress events are forwarded as
``progress`` notifications once it returns. ``compare`` runs both
implementations, as at a terminal.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import io
import json
import os
import queue
import sys
import threading
from collections import Counter
from collections.abc import Callable, Generator, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

import structlog

logger = structlog.get_logger("opentide.cli.services.serve")

#: ``initialize``'s ``protocol``: bumped only when a message changes meaning.
PROTOCOL_VERSION = 1

#: JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602

#: Exit code of a run stopped by ``$/cancelRequest``, as for Ctrl-C.
CANCELLED_EXIT_CODE = 130

#: Commands that never write the workspace, by their first word: the registry
#: they build is kept for the next run in the same workspace. Every other
#: command builds its own, and drops what was kept for its workspace.
READ_ONLY_COMMANDS = frozenset({"validate", "lint", "info", "explain", "commands"})
#: Options that make a read-only command write (``validate --fix``, ``lint --fix``).
WRITING_OPTIONS = frozenset({"--fix"})

#: Variables a run resolving its workspace from ``cwd`` must not inherit.
_WORKSPACE_VARIABLES = ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE")

Message = dict[str, Any]
Writer = Callable[[Message], None]


class ProtocolError(Exception):
    """A message the server cannot act on: answered with a JSON-RPC error."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class RunOutcome:
    """What ``run`` answers: the document and the exit code."""

    document: dict[str, Any]
    exit_code: int

    def to_dict(self) -> dict[str, Any]:
        return {"document": self.document, "exit_code": self.exit_code}


@dataclass
class _Job:
    """One ``run`` in flight, and what a cancel needs to reach it."""

    request_id: Any
    thread_id: int | None = None
    cancelled: bool = False
    finished: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


def _raise_in_thread(thread_id: int, exception: type[BaseException] | None) -> None:
    """Raise *exception* in the thread *thread_id* at its next bytecode; ``None`` clears it."""
    target = ctypes.c_ulong(thread_id)
    if exception is None:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(target, None)
    else:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(target, ctypes.py_object(exception))


def _exit_code(code: object) -> int:
    """``SystemExit.code`` as the process would report it."""
    if code is None:
        return 0
    if isinstance(code, bool):
        return int(code)
    if isinstance(code, int):
        return code
    return 1


def _is_within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _reset_process_caches() -> None:
    """Forget what the previous run cached for its workspace, as a new process would.

    The registry snapshot itself is dropped by the root callback
    (``CliContext.apply_environment``); a kept one comes back from
    ``IndexManager._retained``.
    """
    from opentide.core.root import get_data_root, get_repo_root

    get_repo_root.cache_clear()
    get_data_root.cache_clear()
    # Only what an earlier run imported: importing it here would cost a cold start.
    if "opentide.generation.schema_pipeline" in sys.modules:
        from opentide.generation import schema_pipeline

        schema_pipeline._runtime_ready = False
    if "opentide.core.registry" in sys.modules:
        from opentide.core.registry import Opentide as opentide
        from opentide.platforms.registry import PlatformsRegistry

        opentide._initialised = False
        opentide._objects_loaded = False
        opentide._index = None
        opentide._rules = {}
        opentide._threats = {}
        opentide._objectives = {}
        opentide.Platforms = PlatformsRegistry()


class CommandRunner:
    """Runs ``opentide --json <argv>`` in this process and returns what it printed."""

    def __init__(
        self,
        *,
        base_env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> None:
        self.base_env = dict(os.environ if base_env is None else base_env)
        self.cwd = Path.cwd() if cwd is None else cwd
        #: Registry snapshots of read-only runs, kept between runs (``IndexManager._retained``).
        self.snapshots: dict[Any, Any] = {}
        self._group: Any = None
        #: Whether a run used the Rust engine, whose session may keep workspaces.
        self._used_rust = False
        #: Whether a Rust run is in progress: a cancel interrupts it.
        self._rust_running = False

    @property
    def group(self) -> Any:
        """The root Click group, built once so the command modules it loads stay loaded."""
        if self._group is None:
            import typer

            from opentide.cli.root import app

            self._group = typer.main.get_command(app)
        return self._group

    def command_words(self, argv: Sequence[str]) -> tuple[str, ...]:
        from opentide.cli.lazy import command_words

        try:
            return command_words(self.group, list(argv))
        except Exception:
            return ()

    def keeps_registry(self, argv: Sequence[str]) -> bool:
        """Whether a run of *argv* may use, and keep, a retained registry snapshot."""
        words = self.command_words(argv)
        if not words or words[0] not in READ_ONLY_COMMANDS:
            return False
        options = list(argv[: list(argv).index("--")] if "--" in argv else argv)
        return not any(option.partition("=")[0] in WRITING_OPTIONS for option in options)

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        on_done: Callable[[], None] | None = None,
    ) -> RunOutcome:
        """Run *argv* as ``opentide --json <argv>``; never raises for the command's sake.

        A ``KeyboardInterrupt`` (a cancel) while the command runs is answered
        with exit 130, as at a terminal. *on_done* is called as soon as the
        command has returned, before the cleanup and the parsing of what it
        printed: from then on a cancel must leave its answer alone.
        """
        from opentide.cli.ui.mode import PROTOCOL_COMMANDS
        from opentide.core.index_manager import IndexManager

        if self.command_words(argv)[:2] in PROTOCOL_COMMANDS or self.command_words(argv)[:1] == (
            "tui",
        ):
            # They would read this server's stdin, or draw on a terminal it has not got.
            message = f"opentide {' '.join(self.command_words(argv))} cannot run under serve"
            return RunOutcome(self._usage_document(argv, message), 2)
        keep = self.keeps_registry(argv)
        rust = self._rust_command(argv, env, cwd_given=bool(cwd))
        if rust is not None:
            return self._run_rust(argv, env, cwd, keep=keep, on_done=on_done)
        saved_stdout = sys.stdout
        buffer = io.BytesIO()
        capture = io.TextIOWrapper(buffer, encoding="utf-8", newline="\n", write_through=True)
        directory = Path(cwd) if cwd else self.cwd
        #: The command's exit code, once it has returned.
        code: int | None = None
        try:
            with self._environment(env, cwd_given=bool(cwd)):
                os.chdir(directory)
                _reset_process_caches()
                IndexManager._retained = self.snapshots if keep else None
                sys.stdout = capture
                try:
                    code = self._invoke(["--json", *argv])
                    if on_done is not None:
                        on_done()
                finally:
                    sys.stdout = saved_stdout
                    IndexManager._retained = None
                    IndexManager._cache = None
        except KeyboardInterrupt:
            # A cancel before the command returned, or one that came between its
            # end and the cleanup above: it is raised once, so putting
            # everything back here is enough. A command that had returned keeps
            # its own exit code.
            if code is None:
                code = CANCELLED_EXIT_CODE
            sys.stdout = saved_stdout
            IndexManager._retained = None
            IndexManager._cache = None
            os.environ.clear()
            os.environ.update(self.base_env)
        except OSError as error:
            # A cwd that does not exist: the command never started.
            sys.stdout = saved_stdout
            return RunOutcome(self._failure_document(argv, str(error), 1), 1)
        finally:
            with contextlib.suppress(OSError):
                os.chdir(self.cwd)
            if not keep:
                # It may have written any workspace (--repo names one), so keep none.
                self.snapshots.clear()
                self._clear_rust_workspaces()
        capture.flush()
        text = buffer.getvalue().decode("utf-8", errors="replace")
        return RunOutcome(self._document(argv, text, code), code)

    def run_environment(self, env: Mapping[str, str] | None, *, cwd_given: bool) -> dict[str, str]:
        """The variables a run sees: the server's starting environment, then *env*."""
        values = dict(self.base_env)
        if cwd_given:
            # cwd comes before OPENTIDE_REPO_ROOT: drop the inherited one (an
            # explicit --repo in argv still wins over both).
            for name in _WORKSPACE_VARIABLES:
                values.pop(name, None)
        values.update(env or {})
        if cwd_given and env and "OPENTIDE_REPO_ROOT" in env:
            values.pop("OPENTIDE_REPO_ROOT")
        return values

    def _rust_command(
        self, argv: Sequence[str], env: Mapping[str, str] | None, *, cwd_given: bool
    ) -> Any:
        """The Rust implementation that runs *argv*, or ``None`` when it goes through Python.

        Help is the command tree's (Click's), and ``compare``, an engine that
        is none and ``rust`` for a command without a Rust implementation, or
        for a run it does not cover (``doctor`` without ``--offline``), are
        the dispatcher's, as at a terminal.
        """
        options = list(argv[: list(argv).index("--")] if "--" in argv else argv)
        if "--help" in options or "-h" in options:
            return None
        words = self.command_words(argv)
        if not words:
            return None
        from opentide.cli.engines import rust_command

        return rust_command(words, self.run_environment(env, cwd_given=cwd_given), argv)

    def _run_rust(
        self,
        argv: Sequence[str],
        env: Mapping[str, str] | None,
        cwd: str | None,
        *,
        keep: bool,
        on_done: Callable[[], None] | None,
    ) -> RunOutcome:
        """Run *argv* on its Rust implementation in this process; *keep*: warm."""
        from opentide import __version__
        from opentide.analysis import EngineUnavailableError, engine
        from opentide.core import progress_events

        directory = Path(cwd) if cwd else self.cwd
        if not directory.is_dir():
            message = f"[Errno 2] No such file or directory: {str(directory)!r}"
            return RunOutcome(self._failure_document(argv, message, 1), 1)
        values = self.run_environment(env, cwd_given=bool(cwd))
        values["OPENTIDE_ENGINE"] = "rust"
        # Events come back on stderr, and are forwarded as notifications.
        values[progress_events.PROGRESS_ENV] = progress_events.JSON_VALUE
        try:
            native = engine()
        except EngineUnavailableError as error:
            return RunOutcome(self._failure_document(argv, str(error), 1), 1)
        code: int | None = None
        stdout = stderr = b""
        try:
            self._rust_running = True
            code, stdout, stderr = native.run_cli(
                ["--json", *argv], values, str(directory), __version__, keep
            )
            if on_done is not None:
                on_done()
        except KeyboardInterrupt:
            # A cancel raised once the engine had returned: its answer stands.
            if code is None:
                code = CANCELLED_EXIT_CODE
        except Exception as error:
            # The engine raised instead of answering: a crash, reported as the
            # Python path reports one (error[internal], its crash log).
            code, stdout = self._crash_document(argv, error, values)
        finally:
            self._rust_running = False
            # As after a Python run, the process is back in the server's directory.
            with contextlib.suppress(OSError):
                os.chdir(self.cwd)
            if not keep:
                self.snapshots.clear()
                self._clear_rust_workspaces()
        self._used_rust = True
        self._forward_stderr(stderr)
        text = stdout.decode("utf-8", errors="replace")
        return RunOutcome(self._document(argv, text, code), code)

    @staticmethod
    def _crash_document(
        argv: Sequence[str], error: BaseException, env: Mapping[str, str]
    ) -> tuple[int, bytes]:
        """The exit code and the ``--json`` crash document for *error*, raised by a Rust run."""
        from opentide.cli import _command_path, _raw_command_words
        from opentide.cli.ui.crash import handle_crash

        args = ["--json", *argv]
        buffer = io.StringIO()
        code = handle_crash(
            error,
            argv=args,
            command=_command_path(args),
            words=_raw_command_words(args),
            env=env,
            stdout=buffer,
        )
        return code, buffer.getvalue().encode("utf-8")

    @staticmethod
    def _forward_stderr(stderr: bytes) -> None:
        """A Rust run's stderr: progress events to the run's sink, the rest to stderr."""
        from opentide.core import progress_events

        rest: list[str] = []
        for line in stderr.decode("utf-8", errors="replace").splitlines(keepends=True):
            try:
                event = json.loads(line) if line.startswith("{") else None
            except ValueError:
                event = None
            if isinstance(event, dict) and "event" in event:
                progress_events.emit(event)
            else:
                rest.append(line)
        if rest:
            with contextlib.suppress(OSError, ValueError):
                sys.stderr.write("".join(rest))
                sys.stderr.flush()

    def interrupt_rust(self) -> bool:
        """Interrupt the Rust run in progress, as Ctrl-C would; whether one was."""
        if not self._rust_running:
            return False
        from opentide.analysis import engine

        return bool(engine().interrupt_cli())

    def _clear_rust_workspaces(self) -> None:
        """Forget the Rust session's warm workspaces, if a Rust run kept any."""
        if self._used_rust:
            from opentide.analysis import engine

            engine().clear_workspaces()

    @contextlib.contextmanager
    def _environment(self, env: Mapping[str, str] | None, *, cwd_given: bool) -> Generator[None]:
        """The server's starting environment, then *env*; put back afterwards."""
        values = self.run_environment(env, cwd_given=cwd_given)
        os.environ.clear()
        os.environ.update(values)
        try:
            yield
        finally:
            os.environ.clear()
            os.environ.update(self.base_env)

    def _invoke(self, args: list[str]) -> int:
        """What :func:`opentide.cli.main` does with *args*, returning the exit code."""
        from opentide.cli import _command_path, _raw_command_words
        from opentide.cli.context import sync_typer_rendering

        argv = args
        try:
            options = argv[: argv.index("--")] if "--" in argv else argv
            sync_typer_rendering(no_color="--no-color" in options or bool(os.getenv("NO_COLOR")))
            self.group.main(args=argv, prog_name="opentide", standalone_mode=True)
        except SystemExit as exit_:
            return _exit_code(exit_.code)
        except KeyboardInterrupt:
            from opentide.cli.ui.crash import report_interrupt

            return report_interrupt()
        except Exception as error:
            from opentide.cli.ui.crash import handle_crash

            return handle_crash(
                error, argv=argv, command=_command_path(argv), words=_raw_command_words(argv)
            )
        return 0

    def _document(self, argv: Sequence[str], text: str, code: int) -> dict[str, Any]:
        """The JSON document *text* holds, or one built for a run that printed none."""
        stripped = text.strip()
        if stripped:
            try:
                document = json.loads(stripped)
            except ValueError:
                document = None
            if isinstance(document, dict):
                return document
            # Help or a version line: text, not a document.
            return self._text_document(argv, text, code)
        if code == CANCELLED_EXIT_CODE:
            return self._failure_document(argv, "Interrupted", code)
        return self._failure_document(argv, "The command printed no document", code)

    def _text_document(self, argv: Sequence[str], text: str, code: int) -> dict[str, Any]:
        from opentide.cli.output import envelope

        first = next((line for line in text.splitlines() if line.strip()), "")
        payload = {"ok": code == 0, "status": "completed" if code == 0 else "failed"}
        payload.update({"message": first.strip(), "text": text})
        return envelope(payload, exit_code=code, command=" ".join(self.command_words(argv)))

    def _usage_document(self, argv: Sequence[str], message: str) -> dict[str, Any]:
        from opentide.cli.output import envelope
        from opentide.cli.ui.contract import USAGE_ERROR, USAGE_EXIT_CODE, Failure

        payload = {"error": message, "ok": False, "status": "failed", "message": message}
        return envelope(
            payload,
            exit_code=USAGE_EXIT_CODE,
            failure=Failure(code=USAGE_ERROR, message=message),
            command=" ".join(self.command_words(argv)),
        )

    def _failure_document(self, argv: Sequence[str], message: str, code: int) -> dict[str, Any]:
        from opentide.cli.output import envelope
        from opentide.cli.ui.contract import COMMAND_FAILED, INTERRUPTED, Failure

        failure = Failure(
            code=INTERRUPTED if code == CANCELLED_EXIT_CODE else COMMAND_FAILED, message=message
        )
        payload = {"error": message, "ok": False, "status": "failed", "message": message}
        return envelope(
            payload,
            exit_code=code,
            failure=failure,
            command=" ".join(self.command_words(argv)),
        )

    def invalidate(self, paths: Iterable[str | Path]) -> int:
        """Drop every kept snapshot that *paths* may affect; return how many went.

        A snapshot goes when a path is inside its workspace, its data root or
        its working directory, or contains one of them. A path that matches no
        snapshot drops them all: it may be a file a configuration points at.
        """
        resolved = [Path(path) for path in paths]
        if resolved and self._used_rust:
            from opentide.analysis import engine

            # Taken into account at each warm workspace's next run.
            engine().invalidate_workspaces([str(path) for path in resolved])
        if not resolved or not self.snapshots:
            return 0
        dropped = 0
        matched = False
        for key in list(self.snapshots):
            repo, data, cwd = (Path(part) for part in key[:3])
            workspace = dict(key[3]).get("OPENTIDE_TIDE_WORKSPACE")
            roots = [repo, data, cwd, *([Path(workspace)] if workspace else [])]
            if any(
                _is_within(path, root) or _is_within(root, path)
                for path in resolved
                for root in roots
            ):
                del self.snapshots[key]
                dropped += 1
                matched = True
        if not matched:
            dropped = len(self.snapshots)
            self.snapshots.clear()
        return dropped


def commands_digest(document: Mapping[str, Any]) -> str:
    """sha256 of ``opentide --json commands``'s document, ``duration_ms`` left out.

    Keys are sorted and the JSON is compact, so the digest names the command
    tree and nothing about the run that printed it.
    """
    stable = {key: value for key, value in document.items() if key != "duration_ms"}
    text = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Server:
    """The JSON-RPC loop: reads requests, runs commands one at a time, writes answers.

    *write* sends one message; it is called from several threads, under a lock.
    """

    def __init__(self, write: Writer, *, runner: CommandRunner | None = None) -> None:
        self._write = write
        self._write_lock = threading.Lock()
        self.runner = runner or CommandRunner()
        self._queue: queue.Queue[Message | None] = queue.Queue()
        self._active: _Job | None = None
        #: Ids of queued runs a cancel named: each is answered 130 when it is reached.
        self._cancelled: set[str] = set()
        #: Ids of the runs queued and not yet reached, each as many times as it is queued.
        self._queued: Counter[str] = Counter()
        self._state_lock = threading.Lock()
        self._shut_down = False
        #: Set by ``exit`` or the end of input: queued runs answer 130 unrun.
        self._closing = False
        #: Set when a write to the client fails: nothing more is written.
        self._output_closed = False
        self._digest: str | None = None

    # --- output ---------------------------------------------------------------------

    def send(self, message: Message) -> None:
        """Write *message*; once a write fails, the client has gone and the session ends."""
        with self._write_lock:
            if self._output_closed:
                return
            try:
                self._write({"jsonrpc": "2.0", **message})
                return
            except (OSError, ValueError):
                # A closed pipe (BrokenPipeError), or a write to a closed file.
                self._output_closed = True
        logger.debug("serve_output_closed")
        self._close()

    def _respond(self, request_id: Any, result: Any) -> None:
        self.send({"id": request_id, "result": result})

    def _error(self, request_id: Any, code: int, message: str) -> None:
        self.send({"id": request_id, "error": {"code": code, "message": message}})

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        self.send({"method": method, "params": dict(params)})

    # --- input ----------------------------------------------------------------------

    def receive(self, line: bytes | str) -> None:
        """Take one line from the client. Called on the reading thread.

        A cancel acts at once; everything else is queued in order.
        """
        text = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line
        if not text.strip():
            return
        try:
            message = json.loads(text)
        except ValueError as exc:
            self._error(None, PARSE_ERROR, f"Parse error: {exc}")
            return
        if isinstance(message, list):
            self._error(None, INVALID_REQUEST, "Batches are not supported: send one message a line")
            return
        if not isinstance(message, dict) or not isinstance(message.get("method"), str):
            request_id = message.get("id") if isinstance(message, dict) else None
            self._error(request_id, INVALID_REQUEST, "Invalid request: no method")
            return
        if message["method"] == "$/cancelRequest":
            params = message.get("params")
            if isinstance(params, dict) and "id" in params:
                self.cancel(params["id"])
            return
        if message["method"] == "exit":
            self._close()
            return
        if message["method"] == "run" and "id" in message:
            with self._state_lock:
                self._queued[_id_key(message["id"])] += 1
        self._queue.put(message)

    def close_input(self) -> None:
        """The client closed stdin: as ``exit``."""
        self._close()

    def _close(self) -> None:
        """Stop the running command now and run no queued one, then leave.

        The client has gone, or is going: a queued ``deploy`` or ``generate``
        must not run with nobody to answer. Each queued ``run`` is answered
        ``130`` instead, as a cancelled one is.
        """
        with self._state_lock:
            self._closing = True
        self._cancel_active()
        self._queue.put(None)

    def cancel(self, request_id: Any) -> None:
        """Cancel the ``run`` *request_id*: the running one now, a queued one when it is reached.

        A cancel for a run that has answered, or was never sent, changes nothing:
        a later request that reuses the id runs.
        """
        with self._state_lock:
            job = self._active
            if job is None or job.request_id != request_id:
                if self._queued[_id_key(request_id)] > 0:
                    self._cancelled.add(_id_key(request_id))
                return
        self._interrupt(job)

    def _cancel_active(self) -> None:
        with self._state_lock:
            job = self._active
        if job is not None:
            self._interrupt(job)

    def _interrupt(self, job: _Job) -> None:
        with job.lock:
            if job.finished or job.cancelled or job.thread_id is None:
                job.cancelled = True
                return
            job.cancelled = True
            # A Rust run holds no Python frame to raise in until it returns.
            self.runner.interrupt_rust()
            _raise_in_thread(job.thread_id, KeyboardInterrupt)

    # --- the loop -------------------------------------------------------------------

    def serve(self) -> int:
        """Handle queued messages until ``exit`` or the end of input; return the exit code."""
        while True:
            message = self._queue.get()
            if message is None:
                return 0
            try:
                self._handle(message)
            except Exception:  # pragma: no cover - the loop must outlive any one message
                logger.exception("serve_message_failed", method=message.get("method"))
                if "id" in message:
                    with contextlib.suppress(Exception):
                        self._error(message.get("id"), -32603, "Internal error")

    def _handle(self, message: Message) -> None:
        method = message["method"]
        is_request = "id" in message
        request_id = message.get("id")
        params = message.get("params")
        if params is None:
            params = {}
        if method == "invalidate":
            paths = params.get("paths") if isinstance(params, dict) else None
            if isinstance(paths, list):
                dropped = self.runner.invalidate(str(path) for path in paths)
                logger.debug("serve_invalidated", paths=len(paths), dropped=dropped)
            return
        if not is_request:
            return  # An unknown notification is ignored, as JSON-RPC asks.
        if method == "run":
            with self._state_lock:
                key = _id_key(request_id)
                self._queued[key] -= 1
                if self._queued[key] <= 0:
                    del self._queued[key]
                # Reached: from here on a cancel acts on the running job, or not at all.
                cancelled = key in self._cancelled
                self._cancelled.discard(key)
        else:
            cancelled = False
        if self._shut_down:
            self._error(request_id, INVALID_REQUEST, "The server is shut down; send exit")
            return
        if method == "initialize":
            self._respond(request_id, self.initialize())
        elif method == "run":
            try:
                argv, cwd, env = _run_params(params)
            except ProtocolError as exc:
                self._error(request_id, exc.code, exc.message)
                return
            self._respond(
                request_id, self._run(request_id, argv, cwd, env, cancelled=cancelled).to_dict()
            )
        elif method == "shutdown":
            self._shut_down = True
            self._respond(request_id, None)
        else:
            self._error(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")

    def initialize(self) -> dict[str, Any]:
        from opentide import __version__

        if self._digest is None:
            outcome = self._on_thread(lambda: self.runner.run(["commands"]))
            self._digest = commands_digest(outcome.document)
        return {
            "protocol": PROTOCOL_VERSION,
            "version": __version__,
            "commands_digest": self._digest,
        }

    def _run(
        self,
        request_id: Any,
        argv: list[str],
        cwd: str | None,
        env: dict[str, str] | None,
        *,
        cancelled: bool = False,
    ) -> RunOutcome:
        with self._state_lock:
            if self._closing or cancelled:
                return RunOutcome(
                    self.runner._failure_document(argv, "Interrupted", CANCELLED_EXIT_CODE),
                    CANCELLED_EXIT_CODE,
                )
            job = _Job(request_id)
            self._active = job

        from opentide.core import progress_events

        def forward(event: dict[str, Any]) -> None:
            self.notify("progress", {"id": request_id, "event": event})

        try:
            # Installed from this thread, which a cancel never interrupts.
            with progress_events.sink(forward):
                return self._on_thread(
                    lambda: self.runner.run(
                        argv, cwd=cwd, env=env, on_done=lambda: self._finished(job)
                    ),
                    job=job,
                    argv=argv,
                )
        finally:
            with self._state_lock:
                self._active = None

    @staticmethod
    def _finished(job: _Job) -> None:
        """The command of *job* has returned: a cancel from now on changes nothing."""
        with job.lock:
            job.finished = True
            # A cancel that came as the command ended must not surface later.
            _raise_in_thread(threading.get_ident(), None)

    def _on_thread(
        self,
        work: Callable[[], RunOutcome],
        *,
        job: _Job | None = None,
        argv: Sequence[str] = (),
    ) -> RunOutcome:
        """Run *work* on a thread of its own and wait for it."""
        box: list[RunOutcome] = []
        problem: list[BaseException] = []

        def target() -> None:
            outcome: RunOutcome | None = None
            if job is not None:
                with job.lock:
                    job.thread_id = threading.get_ident()
                    cancelled = job.cancelled
                if cancelled:
                    outcome = RunOutcome({}, CANCELLED_EXIT_CODE)
            while True:
                try:
                    if outcome is None:
                        outcome = work()
                    if job is not None:
                        self._finished(job)
                    break
                except KeyboardInterrupt:
                    if outcome is None:
                        outcome = RunOutcome({}, CANCELLED_EXIT_CODE)
                except BaseException as exc:  # pragma: no cover - the runner never raises
                    problem.append(exc)
                    break
            if outcome is not None:
                box.append(outcome)

        thread = threading.Thread(target=target, name="opentide-serve-run", daemon=True)
        thread.start()
        thread.join()
        if problem:
            raise problem[0]
        outcome = box[0]
        if not outcome.document:
            outcome = RunOutcome(
                self.runner._failure_document(argv, "Interrupted", outcome.exit_code),
                outcome.exit_code,
            )
        return outcome


def _id_key(request_id: Any) -> str:
    """A request id as a set member: ids are numbers or strings, never both at once."""
    return json.dumps(request_id)


def _run_params(params: Any) -> tuple[list[str], str | None, dict[str, str] | None]:
    """``run``'s ``argv``, ``cwd`` and ``env``, or a :class:`ProtocolError`."""
    if not isinstance(params, dict):
        raise ProtocolError(INVALID_PARAMS, "run takes an object: {argv, cwd?, env?}")
    argv = params.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ProtocolError(INVALID_PARAMS, "run needs argv: a non-empty list of strings")
    cwd = params.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        raise ProtocolError(INVALID_PARAMS, "cwd must be a string")
    env = params.get("env")
    if env is not None and (
        not isinstance(env, dict)
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())
    ):
        raise ProtocolError(INVALID_PARAMS, "env must map names to strings")
    # --json is implied. A leading copy is dropped; any other is left where it
    # is, since it may be an option's value (``--query --json``) or follow ``--``,
    # and Click accepts the root flag twice.
    while argv and argv[0] == "--json":
        argv = argv[1:]
    if not argv:
        raise ProtocolError(INVALID_PARAMS, "run needs argv: a command to run")
    return argv, cwd, env


def _lines(descriptor: int) -> Iterator[bytes]:
    """The lines read from *descriptor*, unbuffered, until end of input."""
    pending = b""
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        pending += chunk
        *complete, pending = pending.split(b"\n")
        yield from complete
    if pending:
        yield pending


def serve_stdio(
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    *,
    runner: CommandRunner | None = None,
) -> int:
    """Serve on this process's stdin and stdout until ``exit``; return the exit code.

    The protocol keeps a duplicate of descriptor 1; descriptor 1 itself then
    points at stderr, so nothing a command or a child process writes to
    stdout can reach the client. In the same way it reads a duplicate of
    descriptor 0, which then reads the null device: a run that reads stdin
    (``query -``) or a child process reads nothing, not the client's requests.
    """
    if stdout is None:
        sys.stdout.flush()
        protocol = os.fdopen(os.dup(1), "wb", buffering=0)
        os.dup2(2, 1)
        sys.stdout = sys.stderr
    else:
        protocol = stdout
    if stdin is None:
        requests = os.dup(0)
        null = os.open(os.devnull, os.O_RDONLY)
        os.dup2(null, 0)
        os.close(null)
        sys.stdin = open(os.devnull, encoding="utf-8")  # noqa: SIM115 -- stdin for the process life
        # The raw descriptor, not a file object: a daemon thread blocked in a
        # buffered read holds its lock, and the interpreter aborts on it at exit.
        source: Iterable[bytes] = _lines(requests)
    else:
        source = stdin

    def write(message: Message) -> None:
        data = json.dumps(message, ensure_ascii=False, separators=(",", ":"), default=str)
        protocol.write(data.encode("utf-8") + b"\n")
        protocol.flush()

    if runner is None:
        from opentide.cli import launch_environment

        runner = CommandRunner(base_env=launch_environment())
    server = Server(write, runner=runner)

    def read() -> None:
        try:
            for line in source:
                server.receive(line)
        except (OSError, ValueError):
            pass
        server.close_input()

    threading.Thread(target=read, name="opentide-serve-stdin", daemon=True).start()
    with _stop_on_termination(server) as signalled:
        code = server.serve()
    return 128 + signalled[0] if signalled else code


@contextlib.contextmanager
def _stop_on_termination(server: Server) -> Generator[list[int]]:
    """Turn SIGTERM and SIGHUP into the end of input while *server* serves.

    A run executes on a worker thread, where nothing (``setup --plan``'s
    handler included) can catch a signal: Python's default ended the process
    there, without the run's cleanup, and a plan left the repository's copy in
    the temporary folder. The run is cancelled instead, as by ``exit``, and its
    ``finally`` blocks run. A second signal ends the process at once. An
    ignored signal stays ignored. Yields the signals received.
    """
    import signal

    received: list[int] = []
    if threading.current_thread() is not threading.main_thread():
        yield received
        return

    def stop(signum: int, _frame: object) -> None:
        received.append(signum)
        signal.signal(signum, signal.SIG_DFL)
        # Not here: the handler may run while this thread holds the server's lock.
        threading.Thread(target=server.close_input, name="opentide-serve-stop").start()

    previous: dict[int, Any] = {}
    for name in ("SIGTERM", "SIGHUP"):
        number = getattr(signal, name, None)
        if number is None or signal.getsignal(number) is signal.SIG_IGN:
            continue
        previous[number] = signal.signal(number, stop)
    try:
        yield received
    finally:
        for number, handler in previous.items():
            # None: a handler installed outside Python, which cannot be put back.
            signal.signal(number, signal.SIG_DFL if handler is None else handler)
