"""The ``opentide`` console script and ``python -m opentide``: the command line, in this process.

The command line is Rust, compiled into this package as ``opentide._native``
(``bindings/python/``, built by ``hatch_build.py``). :func:`main` hands it the
arguments and returns its exit code: there is no other implementation to fall
back on, and nothing in between, so Ctrl-C (``error: interrupted``, exit 130)
and SIGTERM reach the command itself (``opentide serve`` exits 143).

When the engine does not load (a damaged install, a platform whose wheel's
module fails to load), :func:`main` says so on stderr and exits 1, as any
other error does: no command can run without it.

The command line loads the platform plugins installed in this environment
(``opentide.plugins``, the ``opentide.platforms`` entry points) itself.
"""

from __future__ import annotations

import sys

#: ``typing.TYPE_CHECKING`` without importing typing, which the console
#: script's start would pay for (UC-3.8b, #960); type checkers read it as True.
TYPE_CHECKING = False

if TYPE_CHECKING:
    from collections.abc import Sequence

#: The exit code when the engine does not load: an error (``docs/cli/exit-codes.md``).
ENGINE_UNAVAILABLE_EXIT = 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``opentide`` with *argv* (``sys.argv[1:]`` when ``None``); the exit code."""
    import importlib

    from opentide import __version__

    args = list(sys.argv[1:] if argv is None else argv)
    try:
        # Through the import system, not the package attribute, as
        # opentide.analysis.engine does: a module that fails to load (or is
        # hidden) is seen as such.
        native = importlib.import_module("opentide._native")
    except ImportError as exc:
        cause = str(exc) or type(exc).__name__
        # As the engine_unavailable page (opentide explain) shows it.
        sys.stderr.write(
            f"error: The opentide analysis engine does not load: {cause}\n"
            "  help: reinstall opentide: pip install --force-reinstall opentide\n"
        )
        return ENGINE_UNAVAILABLE_EXIT
    # Flush what Python buffered before the engine writes to the same streams.
    for stream in (sys.stdout, sys.stderr):
        if stream is not None:
            stream.flush()
    return int(native.cli_main(args, __version__))
