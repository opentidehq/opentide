"""The Rust command line, compiled into ``opentide._native``, run in this process.

``OPENTIDE_ENGINE=rust`` runs a ported command
(:data:`opentide.cli.engines.RUST_COMMANDS`) through :func:`run_in_process`:
the console script does so before Typer is imported
(:mod:`opentide.cli.launch`, UC-3.8b, #960), and the root callback for an
entry point that went through Typer (:func:`opentide.cli.engines.dispatch`).
``python -m opentide.cli.rust`` is the Rust side of ``OPENTIDE_ENGINE=compare``,
which runs each implementation as a child process of its own.
"""

from __future__ import annotations

import os
import sys

#: ``typing.TYPE_CHECKING`` without importing typing, which every Rust run
#: would pay for (UC-3.8b, #960); type checkers read it as True.
TYPE_CHECKING = False

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


def run_in_process(argv: Sequence[str], env: Mapping[str, str] | None = None) -> int:
    """Run the Rust command line on *argv* in this process; its exit code.

    It runs with exactly the environment *env* (this process's when ``None``),
    as a child process started with that environment would, and reads nothing
    else from this package (UC-6.0d, #841: ``doctor`` checks no Python module
    and ``setup mcp`` probes the Rust MCP server); this process's environment
    is put back when it returns. The
    engine releases the GIL while it runs and installs its own Ctrl-C handler:
    Ctrl-C ends the run with ``error: interrupted`` and 130, and a signal
    such as SIGTERM reaches the command itself (``serve`` exits 143).
    """
    from opentide import __version__
    from opentide._native import cli_main

    args = list(argv)
    run_env = dict(os.environ if env is None else env)
    # Flush what Python buffered before the engine writes to the same streams.
    for stream in (sys.stdout, sys.stderr):
        if stream is not None:
            stream.flush()
    saved = dict(os.environ)
    _set_environment(run_env)
    try:
        return cli_main(args, __version__)
    finally:
        _set_environment(saved)


def _set_environment(target: Mapping[str, str]) -> None:
    """Make this process's environment exactly *target*, the variables the engine reads included."""
    for name in [name for name in os.environ if name not in target]:
        del os.environ[name]
    for name, value in target.items():
        if os.environ.get(name) != value:
            os.environ[name] = value


def main() -> int:
    """Run the Rust command line on this process's arguments; its exit code."""
    return run_in_process(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
