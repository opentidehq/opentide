"""Outcome, warning, error and next-step lines for the ``human``, ``plain`` and ``agent`` modes.

Every line is built as a Rich ``Text``, never as markup, so a bracket in a
message or a path prints as written. Lines are printed with ``soft_wrap``: a
long path stays whole (the terminal wraps it, so it can still be selected or
clicked), and a pipe or CI log gets exactly the characters a program would
match.

JSON and MCP modes never reach this module.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Literal

from rich.console import Console
from rich.text import Text

from opentide.cli.ui.contract import NextAction
from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.mode import OutputMode, get_mode

#: ``completed`` → ok, ``issues`` → warning, ``skipped`` → skipped, ``failed`` → failed.
OutcomeKind = Literal["ok", "warning", "skipped", "failed"]

#: At most this many next steps follow an outcome line.
MAX_NEXT_ACTIONS = 3

AGENT_TIP = "add --json for machine-readable output"

_OUTCOME_STYLE: dict[str, str] = {
    "ok": "bold green",
    "warning": "bold yellow",
    "failed": "bold red",
    "skipped": "bold",
}
_LABEL_STYLE: dict[str, str] = {
    "error": "bold red",
    "warning": "bold yellow",
    "note": "bold blue",
    "help": "bold cyan",
    "tip": "bold cyan",
}


def outcome_kind(status: str, *, ok: bool = True) -> OutcomeKind:
    """Map a ``CommandResult`` status onto the glyph its outcome line carries."""
    if not ok or status == "failed":
        return "failed"
    if status == "issues":
        return "warning"
    if status == "skipped":
        return "skipped"
    return "ok"


def _encoding(console: Console) -> str:
    return console.encoding or "utf-8"


def outcome_text(kind: OutcomeKind, message: str, *, encoding: str = "utf-8") -> Text:
    """``✓ message``, ``! message``, ``✗ message`` or ``Skipped: message``."""
    line = Text()
    style = _OUTCOME_STYLE[kind]
    if kind == "skipped":
        line.append("Skipped:", style=style)
    else:
        line.append(glyph(kind, encoding=encoding), style=style)
    line.append(" ")
    line.append(message)
    return line


def labelled_text(label: str, message: str, *, indent: int = 0) -> Text:
    """``error: message``, ``warning: message``, ``  help: message`` and so on."""
    line = Text(" " * indent)
    line.append(f"{label}:", style=_LABEL_STYLE.get(label, "bold"))
    line.append(" ")
    line.append(message)
    return line


def next_action_text(action: NextAction, *, encoding: str = "utf-8") -> Text:
    """``→ opentide lint --fix · rename 2 files to match their names``."""
    line = Text()
    line.append(glyph("next", encoding=encoding), style="bold cyan")
    line.append(" ")
    line.append(action.command, style="bold")
    if action.reason:
        line.append(f" {glyph('separator', encoding=encoding)} ", style="dim")
        line.append(action.reason, style="dim")
    return line


def render_outcome(console: Console, kind: OutcomeKind, message: str) -> None:
    """Print the one outcome line a command ends with."""
    console.print(outcome_text(kind, message, encoding=_encoding(console)), soft_wrap=True)


def render_warnings(console: Console, warnings: Iterable[str]) -> None:
    """One ``warning:`` line each. Printed before the outcome line."""
    for warning in warnings:
        console.print(labelled_text("warning", warning), soft_wrap=True)


def render_notes(console: Console, notes: Sequence[tuple[str, str]]) -> None:
    """Indented ``note:`` / ``help:`` lines under an outcome or an error."""
    for label, text in notes:
        console.print(labelled_text(label, text, indent=2), soft_wrap=True)


def render_error(
    console: Console,
    message: str,
    *,
    notes: Sequence[tuple[str, str]] = (),
    mode: OutputMode | None = None,
) -> None:
    """``error: message`` and its notes, plus the ``--json`` tip in ``agent`` mode."""
    mode = mode or get_mode()
    console.print(labelled_text("error", message), soft_wrap=True)
    render_notes(console, notes)
    if mode is OutputMode.AGENT:
        console.print(labelled_text("tip", AGENT_TIP), soft_wrap=True)


def render_next_actions(console: Console, actions: Sequence[NextAction]) -> None:
    """At most :data:`MAX_NEXT_ACTIONS` ``→`` lines. Printed after the outcome line."""
    encoding = _encoding(console)
    for action in actions[:MAX_NEXT_ACTIONS]:
        console.print(next_action_text(action, encoding=encoding), soft_wrap=True)
