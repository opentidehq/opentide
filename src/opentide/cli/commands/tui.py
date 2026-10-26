"""``opentide tui``: the catalogue, its diagnostics and ATT&CK coverage in a terminal UI.

The command only decides whether the UI can open. The Textual app lives in
:mod:`opentide.cli.tui_app`, imported when it opens, so neither this command's
``--help``, nor anything that walks the command tree, loads Textual.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import typer

from opentide.cli.context import CliContext, get_context
from opentide.cli.output import CommandResult, emit_result
from opentide.cli.ui.contract import USAGE_EXIT_CODE, Failure, NextAction
from opentide.cli.ui.mode import OutputMode, detect_ci, get_mode


def tui_cmd(ctx: typer.Context) -> None:
    """Browse the catalogue and its diagnostics in a terminal UI

    A tree of threats, objectives and rules, each object's YAML and the
    diagnostics from the last validate run, and coverage by ATT&CK technique.
    Run validate, generate and deploy --dry-run from the command palette
    (ctrl+p) or their keys. Needs an interactive terminal: it exits 2 under
    --json, in a pipe, in CI or under a coding agent.
    """
    from opentide.cli.services.tui import USAGE_TUI_NEEDS_TTY

    cli = get_context(ctx)
    mode = get_mode()
    interactive = _interactive()
    if mode is OutputMode.HUMAN and interactive:
        from opentide.cli.tui_app import OpentideTui

        OpentideTui(cli).run()
        return
    data: dict[str, Any] = {}
    reason = _plain_reason(cli) if mode is OutputMode.PLAIN and interactive else None
    if reason is not None:
        # A person at a terminal, put in plain mode by a setting: say which one.
        message = (
            "opentide tui runs only in the human output mode; "
            f"this run is in plain mode because {reason}"
        )
        data["advice"] = "set OPENTIDE_OUTPUT=human to open it anyway"
    elif mode is OutputMode.HUMAN:
        message = "opentide tui needs an interactive terminal; stdin or stdout is not one"
    else:
        message = f"opentide tui needs an interactive terminal; this run is in {mode.value} mode"
    emit_result(
        cli,
        CommandResult(
            message=message,
            ok=False,
            status="failed",
            data={"error": message, **data},
            exit_code=USAGE_EXIT_CODE,
            next_actions=(
                NextAction("opentide info", "catalogue counts and platforms"),
                NextAction("opentide validate", "diagnostics for every object"),
            ),
            failure=Failure(code=USAGE_TUI_NEEDS_TTY, message=message),
        ),
    )


def _interactive() -> bool:
    """Textual reads keys from stdin: a terminal on both ends."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _plain_reason(cli: CliContext) -> str | None:
    """The setting that chose ``plain`` mode at a terminal.

    Settings are read in the order the mode rules read them.
    """
    if os.environ.get("OPENTIDE_OUTPUT", "").strip().lower() == "plain":
        return "OPENTIDE_OUTPUT is plain"
    if cli.no_color:
        return "--no-color was passed"
    if os.environ.get("NO_COLOR"):
        return "NO_COLOR is set"
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return "TERM is dumb"
    if detect_ci() is not None:
        return "a CI environment was detected"
    return None
