"""The ``opentide`` console script and ``python -m opentide``: one process for every engine.

Both are ``opentide._native:main`` (UC-3.8b, #960), which hands its
arguments to :func:`main`. Before Typer, Rich or anything else heavy is
imported, :func:`runs_on_rust` decides which implementation answers, as the
root callback's dispatcher (:func:`opentide.cli.engines.dispatch`) would:

- a run the dispatcher would give the Rust command line runs it here, in
  this process (:func:`opentide.cli.rust.run_in_process`), with the GIL
  released: no Typer, and no child process, so Ctrl-C and SIGTERM reach the
  command itself;
- every other run goes to the Python CLI (:func:`opentide.cli.main`), in this
  process, which answers it as it always has: the default engine, ``python``,
  ``compare``, ``--help`` and ``--version``, shell completion, and the
  refusals (an unknown engine, ``engine_not_ported``, a ``--repo`` that is
  not a folder).

The decision reads ``OPENTIDE_ENGINE``, the defaults
(:mod:`opentide.cli.engine_defaults`) and the dispatch table
(:data:`opentide.cli.engines.RUST_COMMANDS`), none of which imports Typer, and
the command path from the Rust command tree
(``opentide._native.command_words``). Under the default engine, with no
command's default flipped, it reads nothing but the environment.
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
    """Run ``opentide`` with *argv* (``sys.argv[1:]`` when ``None``); the exit code.

    A ``SystemExit`` the Python CLI raises with a message rather than a code
    propagates, as it did from the old console script.
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

    Only a run it would hand to that command line unchanged counts. Anything
    the Python CLI answers before the dispatcher (help, the version, a root
    option it does not know, completion, a ``--repo`` that is not a folder)
    or instead of it (``compare``, a refusal) does not.
    """
    from opentide.cli.engine_defaults import DEFAULT_ENGINES, ENGINE_ENV, RUST

    written = env.get(ENGINE_ENV, "").strip()
    if written not in ("", RUST) or (not written and not DEFAULT_ENGINES):
        # python, compare or not an engine; or no default to read.
        return False
    if any(name.startswith("_") and name.endswith("_COMPLETE") for name in env):
        # Click's shell completion.
        return False
    options = args[: args.index("--")] if "--" in args else args
    if "--help" in options or not _plain_root_options(options):
        return False
    from opentide._native import command_words
    from opentide.cli.engines import RUST_CLI, RUST_COMMANDS, selected

    words = tuple(command_words(list(args)))
    if not words or selected(words, env) != RUST:
        return False
    rust = RUST_COMMANDS.get(words)
    if rust is None or rust.launch != RUST_CLI or not rust.covers(args):
        return False
    # setup is the one command that may name a folder it is about to create.
    return words[:1] == ("setup",) or _repo_is_a_folder(options)


def _plain_root_options(options: Sequence[str]) -> bool:
    """Whether the options before the command are root options the root callback accepts.

    ``--version`` and ``-V`` are answered before the callback, and an option
    the root does not know (``--install-completion`` included), or one
    missing its value, is Click's to answer.
    """
    from opentide.cli import _ROOT_FLAGS, _ROOT_VALUE_OPTIONS

    tokens = iter(options)
    for token in tokens:
        if token == "-" or not token.startswith("-"):
            return True
        if token in _ROOT_FLAGS:
            continue
        if token in _ROOT_VALUE_OPTIONS:
            if next(tokens, None) is None:
                return False
            continue
        if token.partition("=")[0] not in _ROOT_VALUE_OPTIONS:
            return False
    return True


def _repo_is_a_folder(options: Sequence[str]) -> bool:
    """Whether ``--repo``, when the command line gives it, names a folder, as the root requires."""
    repo = None
    tokens = iter(options)
    for token in tokens:
        if token == "--repo":
            repo = next(tokens, None)
        elif token.startswith("--repo="):
            repo = token.partition("=")[2]
    return not repo or os.path.isdir(repo)
