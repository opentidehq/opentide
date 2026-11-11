"""The Python side of ``opentide serve``'s Rust host (UC-3.8, #830).

The host is Rust (``crates/opentide-cli/src/serve``): it reads the
requests, answers them in order, cancels, and runs each command that has a
Rust implementation in this process. What it asks of Python is a
:class:`Bridge` around this package's :class:`~opentide.cli.services.serve.CommandRunner`:

- :meth:`Bridge.plan`: which implementation runs a request (the engine
  selection, ``OPENTIDE_ENGINE`` and each command's default, is this
  package's until every command is ported), and with which environment;
- :meth:`Bridge.run`: the run of a command the selection gives to Python,
  exactly as the Python host ran it, its progress events forwarded as they
  come;
- :meth:`Bridge.interrupt`: a cancel of that run, raised in its thread as
  ``KeyboardInterrupt``, as the Python host raised it.

``opentide serve`` under ``OPENTIDE_ENGINE=rust`` starts one with
:func:`start` (``opentide._native.cli_main``). :class:`RustServer` drives the
same host from this process, as :class:`~opentide.cli.services.serve.Server`
is driven: the tests run the protocol's scenarios on both hosts with it.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from opentide.cli.services.serve import (
    CANCELLED_EXIT_CODE,
    CommandRunner,
    RunOutcome,
    Server,
    Writer,
    _Job,
    _raise_in_thread,
)


def _dumps(value: Any) -> str:
    """*value* as the Python host wrote each message: compact, UTF-8 as is."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


class Bridge:
    """What the Rust host asks of the Python package, around one :class:`CommandRunner`."""

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        self._job: _Job | None = None

    def plan(
        self, argv: Sequence[str], cwd: str | None, env: Mapping[str, str] | None
    ) -> dict[str, Any]:
        """How a run of *argv* goes: its words, a refusal, warm or not, and its Rust run.

        ``rust`` is ``None`` when Python runs it (:meth:`run`); otherwise the
        environment and directory the Rust implementation runs with, as the
        Python host gave them to ``opentide._native.run_cli``.
        """
        from opentide.cli.ui.mode import PROTOCOL_COMMANDS

        words = self.runner.command_words(argv)
        refused = None
        if words[:2] in PROTOCOL_COMMANDS or words[:1] == ("tui",):
            refused = f"opentide {' '.join(words)} cannot run under serve"
        return {
            "words": list(words),
            "refused": refused,
            "keep": self.runner.keeps_registry(argv),
            "rust": None if refused else self.rust_run(argv, cwd, env),
        }

    def rust_run(
        self, argv: Sequence[str], cwd: str | None, env: Mapping[str, str] | None
    ) -> dict[str, Any] | None:
        """The Rust run of *argv*, or ``None`` when the engine selection gives it to Python."""
        from opentide.core import progress_events

        if self.runner._rust_command(argv, env, cwd_given=bool(cwd)) is None:
            return None
        values = self.runner.run_environment(env, cwd_given=bool(cwd))
        values["OPENTIDE_ENGINE"] = "rust"
        # Events come back on stderr, and are forwarded as notifications.
        values[progress_events.PROGRESS_ENV] = progress_events.JSON_VALUE
        directory = Path(cwd) if cwd else self.runner.cwd
        return {"env": values, "cwd": str(directory)}

    def run(
        self,
        argv: Sequence[str],
        cwd: str | None,
        env: Mapping[str, str] | None,
        on_event: Callable[[str], object],
        on_finished: Callable[[], object],
    ) -> str:
        """Run *argv* as the Python host ran it; ``run``'s result as JSON text.

        As ``Server._run`` and ``Server._on_thread``: a cancel
        (:meth:`interrupt`) before the command returned answers 130, one
        after it changes nothing.
        """
        from opentide.core import progress_events

        job = _Job(request_id=None, thread_id=threading.get_ident())
        self._job = job

        def finished() -> None:
            Server._finished(job)
            on_finished()

        def forward(event: dict[str, Any]) -> None:
            on_event(_dumps(event))

        outcome: RunOutcome | None = None
        try:
            with progress_events.sink(forward):
                while True:
                    try:
                        if outcome is None and job.cancelled:
                            outcome = RunOutcome({}, CANCELLED_EXIT_CODE)
                        if outcome is None:
                            outcome = self.runner.run(argv, cwd=cwd, env=env, on_done=finished)
                        Server._finished(job)
                        break
                    except KeyboardInterrupt:
                        if outcome is None:
                            outcome = RunOutcome({}, CANCELLED_EXIT_CODE)
        finally:
            self._job = None
        if not outcome.document:
            outcome = RunOutcome(
                self.runner._failure_document(argv, "Interrupted", outcome.exit_code),
                outcome.exit_code,
            )
        return _dumps(outcome.to_dict())

    def interrupt(self) -> None:
        """Cancel the Python run in progress, as the Python host's ``_interrupt`` did."""
        job = self._job
        if job is None:
            return
        with job.lock:
            if job.finished or job.cancelled or job.thread_id is None:
                job.cancelled = True
                return
            job.cancelled = True
            # A Rust run of the Python path holds no Python frame to raise in.
            self.runner.interrupt_rust()
            _raise_in_thread(job.thread_id, KeyboardInterrupt)

    def invalidate(self, paths: Sequence[str]) -> int:
        """Drop the registries *paths* may affect (the Rust host told its own session)."""
        return self.runner.invalidate(paths)

    def forget(self) -> None:
        """A Rust run may have written a workspace: keep no registry."""
        self.runner.snapshots.clear()


def start(base_env: Mapping[str, str], cwd: str) -> Bridge:
    """The bridge of ``opentide serve`` on Rust: runs start from *base_env* and *cwd*."""
    return Bridge(CommandRunner(base_env=base_env, cwd=Path(cwd)))


class RustServer:
    """The Rust host in this process, driven as :class:`~opentide.cli.services.serve.Server` is.

    *write* sends one message, as a ``dict``.
    """

    def __init__(self, write: Writer, *, runner: CommandRunner | None = None) -> None:
        from opentide import __version__
        from opentide.analysis import engine

        self.runner = runner or CommandRunner()
        self.bridge = Bridge(self.runner)

        def line(text: str) -> None:
            write(json.loads(text))

        self._host = engine().ServeHost(line, self.bridge, __version__)

    def receive(self, line: bytes | str) -> None:
        """Take one line from the client."""
        self._host.receive(line.encode("utf-8") if isinstance(line, str) else bytes(line))

    def close_input(self) -> None:
        """The client closed stdin: as ``exit``."""
        self._host.close_input()

    def serve(self) -> int:
        """Handle queued messages until ``exit`` or the end of input; return the exit code."""
        return int(self._host.serve())

    def pending_cancels(self) -> int:
        """How many queued runs a cancel named that have not been reached."""
        return int(self._host.pending_cancels())


def rust_hosts(env: Mapping[str, str] | None = None) -> bool:
    """Whether ``opentide serve`` runs the Rust host under *env*: the engine selection's."""
    from opentide.cli.engines import rust_command

    return rust_command(("serve",), env) is not None


def server_for(write: Writer, *, runner: CommandRunner | None = None) -> Server | RustServer:
    """The host ``opentide serve`` runs under this process's engine selection."""
    if rust_hosts():
        return RustServer(write, runner=runner)
    return Server(write, runner=runner)
