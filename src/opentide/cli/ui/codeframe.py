"""Diagnostics as code frames, for the ``human``, ``plain`` and ``agent`` modes.

::

    error[vocab_unknown]: Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry
      ╭─▶ objects/rules/sentinel-kql-rule.yaml:8:8
      │
    7 │   modified: 2026-01-02
    8 │   tlp: clearr
      │        ━━━━━━ not in tlp::1.0
      │
      ╰─ help: did you mean 'clear'?

Diagnostics are grouped by file and ordered by line. Lines are Rich ``Text``
printed with ``soft_wrap``, so a source line is never wrapped into the gutter
and a path stays whole. The frame characters fall back to ASCII when the
stream cannot encode them. In ``human`` mode the location is an OSC 8 link.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.text import Text

from opentide.cli.ui.diagnostics import Diagnostic, SourceFiles, relative_path
from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.mode import OutputMode, get_mode

if TYPE_CHECKING:
    from opentide.cli.ui.fixes import FixChange

_SEVERITY_STYLE = {"error": "bold red", "warning": "bold yellow", "note": "bold blue"}
_NOTE_STYLE = {"help": "bold cyan", "note": "bold blue", "expected": "bold", "fix": "bold cyan"}
_GUTTER_STYLE = "blue"

#: ``OPENTIDE_LINKS`` values, and the scheme each one writes.
LINK_SCHEMES = ("file", "vscode", "cursor", "none")


def link_url(
    file_path: Path,
    line: int | None = None,
    column: int | None = None,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """The OSC 8 target for a location: ``file://`` unless the editor can open a line.

    ``OPENTIDE_LINKS`` picks the scheme. Otherwise ``vscode://`` when
    ``TERM_PROGRAM=vscode``, which Cursor reports as well.
    """
    env = os.environ if env is None else env
    scheme = env.get("OPENTIDE_LINKS", "").strip().lower()
    if scheme not in LINK_SCHEMES:
        scheme = "vscode" if env.get("TERM_PROGRAM", "").lower() == "vscode" else "file"
    if scheme == "none":
        return None
    absolute = file_path if file_path.is_absolute() else Path.cwd() / file_path
    if scheme == "file":
        return absolute.as_uri()
    target = absolute.as_posix()
    if line is not None:
        target += f":{line}" + (f":{column}" if column is not None else "")
    return (
        f"{scheme}://file/{target.lstrip('/')}" if os.name == "nt" else f"{scheme}://file{target}"
    )


def display_path(diagnostic: Diagnostic, cwd: Path | None = None) -> str | None:
    """Relative to the current directory when inside it, else to the workspace."""
    if diagnostic.file_path is None:
        return diagnostic.path
    cwd = Path.cwd() if cwd is None else cwd
    shown = relative_path(diagnostic.file_path, cwd)
    if Path(shown).is_absolute() and diagnostic.path is not None:
        return diagnostic.path
    return shown


def _location(diagnostic: Diagnostic, cwd: Path | None) -> str | None:
    shown = display_path(diagnostic, cwd)
    if shown is None:
        return None
    if diagnostic.line is not None:
        shown += f":{diagnostic.line}"
        if diagnostic.column is not None:
            shown += f":{diagnostic.column}"
    return shown


def _notes(diagnostic: Diagnostic) -> list[tuple[str, str]]:
    notes = list(diagnostic.notes)
    if diagnostic.help:
        notes.append(("help", diagnostic.help))
    elif diagnostic.fix is not None and diagnostic.fix.edits:
        replacements = ", ".join(repr(edit.replacement) for edit in diagnostic.fix.edits)
        notes.append(("fix", f"replace with {replacements}"))
    return notes


def diagnostic_lines(
    diagnostic: Diagnostic,
    *,
    sources: SourceFiles,
    encoding: str = "utf-8",
    cwd: Path | None = None,
    links: bool = False,
) -> list[Text]:
    """The lines of one diagnostic's frame."""
    style = _SEVERITY_STYLE.get(diagnostic.severity, "bold")
    header = Text()
    header.append(f"{diagnostic.severity}[{diagnostic.code}]", style=style)
    header.append(": ", style="bold")
    header.append(diagnostic.message, style="bold")
    lines = [header]

    source: str | None = None
    if diagnostic.file_path is not None and diagnostic.line is not None:
        source = sources.line(diagnostic.file_path, diagnostic.line)
    width = len(str(diagnostic.line)) if source is not None and diagnostic.line else 1
    pad = " " * (width + 1)
    bar = glyph("frame_bar", encoding=encoding)
    notes = _notes(diagnostic)
    location = _location(diagnostic, cwd)

    def gutter(number: str = "") -> Text:
        text = Text()
        text.append(f"{number:>{width}} " if number else pad, style=_GUTTER_STYLE)
        text.append(bar, style=_GUTTER_STYLE)
        return text

    if location is not None:
        opener = "frame_open" if source is not None or notes else "frame_only"
        line = Text(pad)
        line.append(glyph(opener, encoding=encoding), style=_GUTTER_STYLE)
        line.append(" ")
        url = (
            link_url(diagnostic.file_path, diagnostic.line, diagnostic.column)
            if (links and diagnostic.file_path is not None)
            else None
        )
        line.append(location, style=f"link {url}" if url else "")
        lines.append(line)

    if source is not None and diagnostic.line is not None:
        lines.append(gutter())
        previous = (
            sources.line(diagnostic.file_path, diagnostic.line - 1)
            if (diagnostic.file_path is not None)
            else None
        )
        if previous is not None and previous.strip():
            row = gutter(str(diagnostic.line - 1))
            row.append(" " + previous.rstrip())
            lines.append(row)
        row = gutter(str(diagnostic.line))
        row.append(" " + source.rstrip())
        lines.append(row)
        if diagnostic.column is not None:
            length = max(1, (diagnostic.end_column or diagnostic.column + 1) - diagnostic.column)
            row = gutter()
            row.append(" " + " " * (diagnostic.column - 1))
            row.append(glyph("underline", encoding=encoding) * length, style=style)
            if diagnostic.label:
                row.append(" " + diagnostic.label, style=style)
            lines.append(row)
        if notes:
            lines.append(gutter())

    for index, (label, text) in enumerate(notes):
        last = index == len(notes) - 1
        row = Text(pad)
        row.append(
            glyph("frame_close" if last else "frame_note", encoding=encoding), style=_GUTTER_STYLE
        )
        row.append(" ")
        row.append(f"{label}:", style=_NOTE_STYLE.get(label, "bold"))
        row.append(" " + text)
        lines.append(row)
    return lines


def sort_diagnostics(diagnostics: Iterable[Diagnostic]) -> list[Diagnostic]:
    """Grouped by file (files first, in path order), then by line."""
    return sorted(
        diagnostics,
        key=lambda item: (item.path is None, item.path or "", item.line or 0, item.column or 0),
    )


def render_diagnostics(
    console: Console,
    diagnostics: Sequence[Diagnostic],
    *,
    sources: SourceFiles | None = None,
    mode: OutputMode | None = None,
    quiet: bool = False,
    cwd: Path | None = None,
) -> None:
    """Print each diagnostic as a code frame, a blank line after each one.

    ``quiet`` keeps errors only. JSON and MCP modes never reach this function.
    """
    mode = mode or get_mode()
    sources = sources or SourceFiles()
    encoding = console.encoding or "utf-8"
    shown = [item for item in diagnostics if not quiet or item.severity == "error"]
    for diagnostic in sort_diagnostics(shown):
        for line in diagnostic_lines(
            diagnostic,
            sources=sources,
            encoding=encoding,
            cwd=cwd,
            links=mode is OutputMode.HUMAN,
        ):
            console.print(line, soft_wrap=True)
        console.print()


# --------------------------------------------------------------------------
# validate --fix
# --------------------------------------------------------------------------

_DIFF_STYLE = (("+++", "bold"), ("---", "bold"), ("@@", "cyan"), ("+", "green"), ("-", "red"))


def render_diff(console: Console, diff: str) -> None:
    """A unified diff, ``+`` lines green and ``-`` lines red, then a blank line."""
    if not diff:
        return
    for raw in diff.splitlines():
        style = next((style for prefix, style in _DIFF_STYLE if raw.startswith(prefix)), "")
        console.print(Text(raw, style=style), soft_wrap=True)
    console.print()


def render_fixed(
    console: Console, changes: Sequence[FixChange], *, cwd: Path | None = None
) -> None:
    """``fixed: objects/rules/x.yaml:8:8 'clearr' → 'clear'``, one line per value replaced."""
    if not changes:
        return
    encoding = console.encoding or "utf-8"
    base = Path.cwd() if cwd is None else cwd
    for change in changes:
        shown = relative_path(change.file_path, base)
        if Path(shown).is_absolute():
            shown = change.path
        line = Text()
        line.append("fixed:", style="bold green")
        line.append(f" {shown}:{change.line}:{change.column} {change.before!r} ")
        line.append(glyph("next", encoding=encoding))
        line.append(f" {change.after!r}")
        console.print(line, soft_wrap=True)
    console.print()
