"""``python -m opentide.cli.rust``: the Rust command line, compiled into ``opentide._native``.

``OPENTIDE_ENGINE=rust`` and ``compare`` run a ported command here
(:data:`opentide.cli.engines.RUST_COMMANDS`); it prints and exits as the
command does. The Python launcher replaces it in UC-3.8 (#830).
"""

from __future__ import annotations

import sys


def main() -> int:
    """Run the Rust CLI on this process's arguments; its exit code."""
    from opentide import __version__
    from opentide._native import cli_main

    # Flush what Python buffered before the engine writes to the same streams.
    sys.stdout.flush()
    sys.stderr.flush()
    return cli_main(sys.argv[1:], __version__)


if __name__ == "__main__":
    raise SystemExit(main())
