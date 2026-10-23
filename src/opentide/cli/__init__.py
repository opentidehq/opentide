"""opentide Typer CLI application.

Importing this package stays cheap: :func:`main` answers ``--version`` before
Typer is imported, the root app lives in :mod:`opentide.cli.root`, and each
command module loads only when its command runs (:mod:`opentide.cli.commands`).
"""

from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentide.cli.root import app
    from opentide.core.logging import print_banner as print_banner

__all__ = ["app", "main"]

#: Names this package re-exports without importing them up front.
_LAZY_EXPORTS = {
    "app": "opentide.cli.root",
    "print_banner": "opentide.core.logging",
}

# The root options, as `opentide.cli.root.main_callback` declares them.
# tests/test_cli/test_lazy_commands.py checks the two still agree.
_VERSION_FLAGS = frozenset({"--version", "-V"})
_ROOT_FLAGS = frozenset({"--debug", "--no-color", "--json", "--quiet"})
_ROOT_VALUE_OPTIONS = frozenset({"--repo", "--data", "--proxy"})


def __getattr__(name: str) -> object:
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)


def _asks_only_for_version(argv: Sequence[str]) -> bool:
    """Whether the root app would answer *argv* by printing the version.

    Follows how Click parses the root options: they end at the first token
    that is not an option (the command) or at ``--``, and ``--repo``,
    ``--data`` and ``--proxy`` take the next token even when it looks like an
    option. Anything this does not recognise, ``--help`` included, returns
    False and goes to Typer, which answers it as it always has.
    """
    asked = False
    tokens = iter(argv)
    for token in tokens:
        if token in ("-", "--") or not token.startswith("-"):
            break
        if token in _VERSION_FLAGS:
            asked = True
        elif token in _ROOT_VALUE_OPTIONS:
            if next(tokens, None) is None:
                return False
        elif token not in _ROOT_FLAGS and token.partition("=")[0] not in _ROOT_VALUE_OPTIONS:
            return False
    return asked


def main() -> None:
    """Console script entry point."""
    argv = sys.argv[1:]
    if _asks_only_for_version(argv):
        # Before Typer, Rich or the registry: a pipeline that logs the version
        # it installed should not pay for them.
        from opentide import __version__

        sys.stdout.write(f"opentide {__version__}\n")
        sys.stdout.flush()
        return

    from opentide.cli.context import sync_typer_rendering
    from opentide.cli.root import app

    # Here rather than at import: opentide.ci imports this package, and a host
    # Typer app must keep its own rendering settings. Click parses root
    # options, and exits on a bad one, before the eager callback runs.
    options = argv[: argv.index("--")] if "--" in argv else argv
    sync_typer_rendering(no_color="--no-color" in options or bool(os.getenv("NO_COLOR")))
    app()


if __name__ == "__main__":
    main()
