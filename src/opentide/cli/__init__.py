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


def _print_version(line: str) -> None:
    """Write *line* the way ``typer.echo`` under Click's ``main()`` did.

    No stdout (a closed descriptor, a ``pythonw`` launcher) prints nothing and
    exits 0. A pipe whose reader has gone exits 1 without a traceback.
    """
    out = sys.stdout
    if out is None:
        return
    try:
        out.write(line)
        out.flush()
    except BrokenPipeError:
        # Nothing is left for the interpreter to flush on the way out.
        sys.stdout = None
        raise SystemExit(1) from None


def main() -> None:
    """Console script entry point."""
    argv = sys.argv[1:]
    if _asks_only_for_version(argv):
        # Before Typer, Rich or the registry: a pipeline that logs the version
        # it installed should not pay for them.
        from opentide import __version__

        _print_version(f"opentide {__version__}\n")
        return

    try:
        from opentide.cli.context import sync_typer_rendering
        from opentide.cli.root import app

        # Here rather than at import: opentide.ci imports this package, and a
        # host Typer app must keep its own rendering settings. Click parses root
        # options, and exits on a bad one, before the eager callback runs.
        options = argv[: argv.index("--")] if "--" in argv else argv
        sync_typer_rendering(no_color="--no-color" in options or bool(os.getenv("NO_COLOR")))
        app()
    except KeyboardInterrupt:
        # Typer turns Ctrl-C inside a command into exit 130 itself; this is
        # Ctrl-C while the CLI was still loading.
        from opentide.cli.ui.crash import report_interrupt

        raise SystemExit(report_interrupt()) from None
    except Exception as error:
        # SystemExit, typer.Exit and Click's usage errors never get here:
        # Click's standalone mode turns them into an exit code first.
        try:
            from opentide.cli.ui.crash import handle_crash

            code = handle_crash(
                error, argv=argv, command=_command_path(argv), words=_raw_command_words(argv)
            )
        except BaseException:
            # Even Ctrl-C while reporting: exit 1, and never Python's chained
            # traceback, which would print the unredacted original.
            code = 1
        raise SystemExit(code) from None


def _raw_command_words(argv: Sequence[str]) -> tuple[str, ...]:
    """The first two command words of *argv*, read without Typer: ``("mcp", "start")``.

    Root options are skipped wherever they appear, as they are hoisted; the
    words end at any other option.
    """
    words: list[str] = []
    tokens = iter(argv)
    for token in tokens:
        if token == "--" or len(words) == 2:
            break
        if token in _ROOT_FLAGS or token in _VERSION_FLAGS:
            continue
        if token in _ROOT_VALUE_OPTIONS:
            next(tokens, None)
            continue
        if token.startswith("-"):
            if token.partition("=")[0] in _ROOT_VALUE_OPTIONS:
                continue
            break
        words.append(token)
    return tuple(words)


def _command_path(argv: Sequence[str]) -> str:
    """The command path *argv* names (``generate docs rules``), without argument values."""
    try:
        import typer

        from opentide.cli.lazy import command_words
        from opentide.cli.root import app

        return " ".join(command_words(typer.main.get_command(app), argv))
    except Exception:
        return ""


if __name__ == "__main__":
    main()
