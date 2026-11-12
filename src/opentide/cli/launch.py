"""The ``opentide`` console script and ``python -m opentide``: one process for every engine.

Both are :func:`main` (UC-3.8b, #960). Unless the environment and the root
options alone give the run to Python, it loads the engine,
``opentide._native``, and hands its arguments to ``opentide._native.main``,
which hands them back to :func:`run`. When the engine does not load (a
damaged install, a platform whose wheel's module fails to load), the Python
CLI answers every run, as it did before this launcher: the commands that need
the engine fail with ``engine_unavailable``, and the others work.

Before Typer, Rich or anything else heavy is imported, :func:`runs_on_rust`
decides which implementation answers, as the root callback's dispatcher
(:func:`opentide.cli.engines.dispatch`) would:

- a run the dispatcher would give the Rust command line runs it here, in
  this process (:func:`opentide.cli.rust.run_in_process`), with the GIL
  released: no Typer, and no child process, so Ctrl-C and SIGTERM reach the
  command itself;
- every other run goes to the Python CLI (:func:`opentide.cli.main`), in this
  process, which answers it as it always has: the default engine, ``python``,
  ``compare``, Typer's completion requests (``_OPENTIDE_COMPLETE``), and the
  refusals (an unknown engine, ``engine_not_ported``).

Under ``rust``, the root's own runs are the Rust command line's too (#841):
``--help`` on any command it has, ``--version``, ``--show-completion`` and
``--install-completion``, a bare ``opentide`` (the home screen, or the
help), a bare group, a mistyped command or root option and a ``--repo`` that
is not a folder.

The decision reads ``OPENTIDE_ENGINE``, the defaults
(:mod:`opentide.cli.engine_defaults`) and the dispatch table
(:data:`opentide.cli.engines.RUST_COMMANDS`), none of which imports Typer, and
the command path from the Rust command tree
(``opentide._native.command_words``). Under the default engine, with no
command's default flipped, it reads nothing but the environment and the
arguments: a ``--platform`` outside the built-in platforms may name a
platform plugin, whose run goes to Rust (UC-4.5b,
:func:`opentide.cli.engines.plugin_default`).
"""

from __future__ import annotations

import os
import sys

#: ``typing.TYPE_CHECKING`` without importing typing, which the console
#: script's start would pay for (UC-3.8b, #960); type checkers read it as True.
TYPE_CHECKING = False

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """The console script: run ``opentide`` with *argv* (``sys.argv[1:]`` when ``None``).

    Through the engine (``opentide._native.main``, then :func:`run`) when the
    run may be Rust's and the engine loads, else on the Python CLI alone; the
    exit code. A run the environment alone gives to Python (the default
    engine, ``python``, ``compare``) does not load the engine first.
    """
    import importlib

    args = list(sys.argv[1:] if argv is None else argv)
    try:
        maybe = _may_run_on_rust(args, os.environ)
    except KeyboardInterrupt:
        from opentide.cli.ui.crash import report_interrupt

        return report_interrupt()
    except Exception:
        # Not a failure turned into success: the Python CLI answers the run.
        maybe = False
    if not maybe:
        return run_python(argv)
    try:
        # Through the import system, not the package attribute, as
        # opentide.analysis.engine does: a module that fails to load (or is
        # hidden) is seen as such.
        native = importlib.import_module("opentide._native")
    except ImportError:
        # The engine is missing or does not load: the Python CLI answers, and
        # a command that needs the engine fails with engine_unavailable.
        return run_python(argv)
    return native.main(None if argv is None else list(argv))


def run(argv: Sequence[str] | None = None) -> int:
    """Run ``opentide`` with *argv* on Rust or Python, as the dispatcher would; the exit code.

    ``opentide._native.main`` calls it. A ``SystemExit`` the Python CLI raises
    with a message rather than a code propagates, as it did from the old
    console script.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        rust = runs_on_rust(args, os.environ)
    except KeyboardInterrupt:
        from opentide.cli.ui.crash import report_interrupt

        return report_interrupt()
    except Exception:
        # Not a failure turned into success: the Python CLI answers the run
        # instead, as it did before this launcher, and reports what it finds.
        rust = False
    if rust:
        from opentide.cli.engine_defaults import ENGINE_ENV, RUST
        from opentide.cli.rust import run_in_process

        # As the root callback's dispatcher starts the Rust command line: with
        # this environment, the engine named (a default of rust included).
        return run_in_process(args, {**os.environ, ENGINE_ENV: RUST})
    return run_python(argv)


def run_python(argv: Sequence[str] | None = None) -> int:
    """Run ``opentide`` with *argv* on the Python CLI (:func:`opentide.cli.main`); the exit code."""
    from opentide.cli import main as python_main

    try:
        python_main(argv)
    except SystemExit as exit_:
        code = exit_.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        raise
    return 0


def runs_on_rust(args: Sequence[str], env: Mapping[str, str]) -> bool:
    """Whether the dispatcher would run *args* on the Rust command line compiled in.

    Only a run it would hand to that command line unchanged counts: the
    command path its tree reads (``()`` for the root's own runs: the help,
    the version, completion, a bare ``opentide``, a mistyped command) is in
    :data:`~opentide.cli.engines.RUST_COMMANDS` and covers the run. Anything
    the Python CLI answers instead (``compare``, a refusal) does not.
    """
    if not _may_run_on_rust(args, env):
        return False
    from opentide._native import command_words
    from opentide.cli.engine_defaults import RUST
    from opentide.cli.engines import RUST_CLI, RUST_COMMANDS, plugin_default, selected

    words = tuple(command_words(list(args)))
    if selected(words, env) != RUST and not plugin_default(words, args, env):
        return False
    rust = RUST_COMMANDS.get(words)
    return rust is not None and rust.launch == RUST_CLI and rust.covers(args)


def _may_run_on_rust(args: Sequence[str], env: Mapping[str, str]) -> bool:
    """What :func:`runs_on_rust` reads from the environment and the platforms *args* name.

    False: Python answers, whatever the command. It needs neither the engine
    nor the command tree.
    """
    from opentide.cli.engine_defaults import (
        DEFAULT_ENGINES,
        ENGINE_ENV,
        RUST,
        names_other_platform,
    )

    written = env.get(ENGINE_ENV, "").strip()
    if written not in ("", RUST) or (
        not written and not DEFAULT_ENGINES and not names_other_platform(args)
    ):
        # python, compare or not an engine; or no default to read and no
        # platform that may be a plugin's (UC-4.5b).
        return False
    # A completion script Typer installed asks the Python CLI (Click's
    # protocol); the Rust command line's scripts never call back.
    return not any(name.startswith("_") and name.endswith("_COMPLETE") for name in env)
