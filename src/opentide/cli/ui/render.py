"""Outcome, warning, error and next-step lines for the ``human``, ``plain`` and ``agent`` modes.

Every line is built as a Rich ``Text``, never as markup, so a bracket in a
message or a path prints as written. Lines are printed with ``soft_wrap``: a
pipe or CI log gets exactly the characters a program would match. At a
terminal, a line wider than the window is broken between words, its
continuation indented under the text, as a code frame's message is (the
terminal broke ``$SPLUNK_TOKEN`` mid-word: post-merge AFTER shots). A word is
never split: a long path stays whole, so it can still be selected or clicked.

JSON and MCP modes never reach this module.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Literal

from rich.cells import cell_len
from rich.console import Console
from rich.text import Text

from opentide.cli.ui.contract import NextAction
from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.mode import OutputMode, get_mode

#: ``completed`` → ok, ``issues`` → warning, ``skipped`` → skipped, ``failed`` → failed.
#: ``plan`` is a dry run's tally (``Plan: 1 to create, …``): nothing happened, so no glyph.
OutcomeKind = Literal["ok", "warning", "skipped", "failed", "plan"]

#: At most this many next steps follow an outcome line.
MAX_NEXT_ACTIONS = 3

AGENT_TIP = "add --json for machine-readable output"

_OUTCOME_STYLE: dict[str, str] = {
    "ok": "bold green",
    "warning": "bold yellow",
    "failed": "bold red",
    "skipped": "bold",
    "plan": "bold",
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
    """``✓ message``, ``! message``, ``✗ message``, ``Skipped: message`` or ``Plan: …``."""
    line = Text()
    style = _OUTCOME_STYLE[kind]
    if kind == "plan":
        label, colon, rest = message.partition(":")
        if colon and " " not in label:
            line.append(label + colon, style=style)
            line.append(rest)
        else:
            line.append(message)
        return line
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


def print_line(console: Console, line: Text, *, hang: int) -> None:
    """Print *line*; at a terminal narrower than it, wrap at words, *hang* cells in.

    A pipe, a file or a CI log keeps the one line, unwrapped, as before.
    """
    width = console.width if console.is_terminal else 0
    if not width or line.cell_len <= width or hang >= width // 2:
        console.print(line, soft_wrap=True)
        return
    for part in word_wrap(line, width, hang):
        console.print(part, soft_wrap=True)


def word_wrap(line: Text, width: int, hang: int) -> list[Text]:
    """*line* broken at spaces into rows of *width* cells, rows after the first *hang* in.

    Only between words: a word is never split, so a path or URL wider than a
    row stays whole (the terminal wraps it and it can still be selected). The
    first row keeps the label and the first word of the message together.
    """
    plain = line.plain
    words = [(match.start(), match.end()) for match in re.finditer(r"\S+", plain)]
    rows: list[tuple[int, int]] = []
    start, end, count = 0, 0, 0
    for word_start, word_end in words:
        room = width if not rows else width - hang
        too_wide = cell_len(plain[start:word_end]) > room
        if too_wide and count >= (2 if not rows else 1):
            rows.append((start, end))
            start, count = word_start, 0
        end, count = word_end, count + 1
    rows.append((start, len(plain)))
    pad = Text(" " * hang)
    return [line[a:b] if index == 0 else pad + line[a:b] for index, (a, b) in enumerate(rows)]


def print_labelled(console: Console, label: str, message: str, *, indent: int = 0) -> None:
    """``label: message``, continued under the message when it wraps."""
    print_line(
        console,
        labelled_text(label, message, indent=indent),
        hang=indent + cell_len(label) + 2,
    )


def render_outcome(console: Console, kind: OutcomeKind, message: str) -> None:
    """Print the one outcome line a command ends with."""
    line = outcome_text(kind, message, encoding=_encoding(console))
    lead = line.plain.find(" ") + 1
    print_line(console, line, hang=lead if 0 < lead <= 10 else 2)


def render_warnings(console: Console, warnings: Iterable[str]) -> None:
    """One ``warning:`` line each. Printed before the outcome line."""
    for warning in warnings:
        print_labelled(console, "warning", warning)


def render_notes(console: Console, notes: Sequence[tuple[str, str]]) -> None:
    """Indented ``note:`` / ``help:`` lines under an outcome or an error."""
    for label, text in notes:
        print_labelled(console, label, text, indent=2)


def render_error(
    console: Console,
    message: str,
    *,
    notes: Sequence[tuple[str, str]] = (),
    mode: OutputMode | None = None,
    tip: bool = True,
) -> None:
    """``error: message`` and its notes, plus the ``--json`` tip in ``agent`` mode.

    *tip* ``False`` leaves the tip to the caller, which prints it after the
    next steps, as the last line.
    """
    mode = mode or get_mode()
    print_labelled(console, "error", message)
    render_notes(console, notes)
    if tip:
        render_agent_tip(console, mode)


def render_agent_tip(console: Console, mode: OutputMode | None = None) -> None:
    """``tip: add --json for machine-readable output``, in ``agent`` mode only."""
    if (mode or get_mode()) is OutputMode.AGENT:
        print_labelled(console, "tip", AGENT_TIP)


def render_next_actions(
    console: Console, actions: Sequence[NextAction], *, numbered: bool = False
) -> None:
    """At most :data:`MAX_NEXT_ACTIONS` ``→`` lines. Printed after the outcome line.

    *numbered* prints them as an ordered list under a ``Next steps`` header,
    for a sequence the reader follows step by step (``setup``).
    """
    encoding = _encoding(console)
    shown = actions[:MAX_NEXT_ACTIONS]
    if not shown:
        return
    if not numbered:
        for action in shown:
            print_line(console, next_action_text(action, encoding=encoding), hang=2)
        return
    from opentide.cli.ui import brand

    console.print()
    if brand.can_draw(console):
        console.print(brand.header("Next steps", mono=brand.is_mono(console), encoding=encoding))
    else:
        console.print(Text("Next steps", style="bold"))
    for number, action in enumerate(shown, start=1):
        line = Text(f"  {number}  ", style="dim")
        line.append(action.command, style="bold")
        if action.reason:
            line.append(f" {glyph('separator', encoding=encoding)} ", style="dim")
            line.append(action.reason, style="dim")
        print_line(console, line, hang=5)
