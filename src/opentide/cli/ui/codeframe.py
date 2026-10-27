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
stream cannot encode them, and any text the stream cannot encode (an emoji in
a YAML comment on a cp1252 pipe) prints as ``?``. The underline is placed by
terminal cell, so it stays under its value after a tab or a wide character.
In ``human`` mode the location is an OSC 8 link.
"""

from __future__ import annotations

import codecs
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

from rich.cells import cell_len
from rich.console import Console
from rich.style import Style
from rich.text import Text

from opentide.cli.ui.diagnostics import Diagnostic, SourceFiles, engine_reference, relative_path
from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.mode import OutputMode, get_mode

if TYPE_CHECKING:
    from opentide.cli.ui.fixes import FixChange

_SEVERITY_STYLE = {"error": "bold red", "warning": "bold yellow", "note": "bold blue"}
_NOTE_STYLE = {"help": "bold cyan", "note": "bold blue", "expected": "bold", "fix": "bold cyan"}
_GUTTER_STYLE = "blue"

#: HighlightSpec capture → terminal style, for the query lines of a frame.
#: Captures not listed (variables, properties, punctuation, Tide keys) keep
#: the terminal's colour.
QUERY_STYLES = {
    "keyword": "bold magenta",
    "operator": "magenta",
    "operator.pipe": "bold magenta",
    "function": "cyan",
    "function.builtin": "cyan",
    "macro": "cyan",
    "type": "bright_cyan",
    "string": "green",
    "number": "yellow",
    "boolean": "yellow",
    "constant": "yellow",
    "comment": "dim",
    "error": "red",
}

#: ``(column, end_column, style)`` spans for one source line of a file.
LineStyles = Callable[[Path, int], list[tuple[int, int, str]]]

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
    # Percent-encoded like a file URI, so a space or a '#' cannot end the target.
    target = quote(absolute.as_posix(), safe="/:")
    if line is not None:
        target += f":{line}" + (f":{column}" if column is not None else "")
    return (
        f"{scheme}://file/{target.lstrip('/')}" if os.name == "nt" else f"{scheme}://file{target}"
    )


def encodable(text: str, encoding: str) -> str:
    """*text* with each character *encoding* cannot write replaced by ``?``."""
    try:
        codecs.lookup(encoding)
    except LookupError:
        return text
    return text.encode(encoding, errors="replace").decode(encoding, errors="replace")


def underline_offset(source: str, column: int) -> str:
    """Blanks that reach *column* in *source* as the terminal draws it.

    Tabs are kept, so they expand to the same stop as in the source line, and
    a wide character becomes as many spaces as the cells it takes.
    """
    return "".join(char if char == "\t" else " " * cell_len(char) for char in source[: column - 1])


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


def wrap_text(text: Text, width: int, indent: Text) -> list[Text]:
    """*text* in lines of at most *width* cells, each after the first led by *indent*.

    Breaks at a space, or after a ``/`` inside a word too long for the line (a
    path), and mid-word only when neither is there. Styles carry over.
    """
    lines: list[Text] = []
    plain = text.plain
    start, room = 0, width
    while cell_len(plain[start:]) > room > 0:
        window = plain[start : start + room + 1]
        space = window.rfind(" ")
        slash = window[:room].rfind("/")
        if space > 0:
            end, resume = start + space, start + space + 1
        elif slash > 0:
            end = resume = start + slash + 1
        else:
            end = resume = start + room
        lines.append(text[start:end])
        start, room = resume, width - indent.cell_len
    lines.append(text[start:])
    return [line if index == 0 else indent + line for index, line in enumerate(lines)]


def shorten_path(location: str, room: int) -> str:
    """*location* in at most *room* cells, its middle folders replaced by ``…``.

    Keeps the first folder, the file name and the ``:line:col``; cuts the
    middle of what is left only when even that is too long.
    """
    if cell_len(location) <= room or room < 1:
        return location
    parts = location.split("/")
    if len(parts) > 2:
        kept = parts[-1:]
        # Put folders back from the file outwards while they fit.
        for part in reversed(parts[1:-1]):
            candidate = "/".join([parts[0], "…", part, *kept])
            if cell_len(candidate) > room:
                break
            kept.insert(0, part)
        shortened = "/".join([parts[0], "…", *kept])
        if cell_len(shortened) <= room:
            return shortened
    head = max(1, (room - 1) // 3)
    tail = max(1, room - 1 - head)
    return f"{location[:head]}…{location[-tail:]}"


def diagnostic_lines(
    diagnostic: Diagnostic,
    *,
    sources: SourceFiles,
    encoding: str = "utf-8",
    cwd: Path | None = None,
    links: bool = False,
    columns: int | None = None,
    styles: LineStyles | None = None,
) -> list[Text]:
    """The lines of one diagnostic's frame.

    With *styles*, the source lines of a query finding are coloured as the
    editor colours them (see :class:`QueryHighlighter`).

    With *columns* (the terminal's width), the message and notes wrap at word or
    path-segment boundaries and the location is shortened in the middle, so
    the terminal never breaks a word. Without one (a pipe, a file), lines are
    whole, for a reader that wraps them itself.
    """
    style = _SEVERITY_STYLE.get(diagnostic.severity, "bold")

    def safe(text: str) -> str:
        return encodable(text, encoding)

    header = Text()
    header.append(f"{diagnostic.severity}[{diagnostic.code}]", style=style)
    header.append(": ", style="bold")
    header.append(safe(diagnostic.message), style="bold")
    lines = wrap_text(header, columns, Text("  ")) if columns else [header]

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
        shown = safe(location)
        if columns:
            shown = shorten_path(shown, columns - line.cell_len)
        line.append(shown, style=Style(link=url) if url else "")
        lines.append(line)

    if source is not None and diagnostic.line is not None:
        lines.append(gutter())
        previous = (
            sources.line(diagnostic.file_path, diagnostic.line - 1)
            if (diagnostic.file_path is not None)
            else None
        )
        highlighted = styles if engine_reference(diagnostic.code) is not None else None

        def source_text(text: str, number: int) -> Text:
            shown = safe(text.rstrip())
            line = Text(" " + shown)
            if highlighted is None or diagnostic.file_path is None or shown != text.rstrip():
                # A character the stream cannot encode moved the columns.
                return line
            for column, end_column, span_style in highlighted(diagnostic.file_path, number):
                line.stylize(span_style, column, end_column)
            return line

        if previous is not None and previous.strip():
            row = gutter(str(diagnostic.line - 1))
            row.append_text(source_text(previous, diagnostic.line - 1))
            lines.append(row)
        row = gutter(str(diagnostic.line))
        row.append_text(source_text(source, diagnostic.line))
        lines.append(row)
        if diagnostic.column is not None:
            # Measured on the text as printed: a replaced character is one cell.
            shown = safe(source)
            end = diagnostic.end_column or diagnostic.column + 1
            marked = shown[diagnostic.column - 1 : end - 1].replace("\t", " ")
            length = max(1, cell_len(marked) if marked else end - diagnostic.column)
            row = gutter()
            row.append(" " + underline_offset(shown, diagnostic.column))
            row.append(glyph("underline", encoding=encoding) * length, style=style)
            if diagnostic.label:
                label = safe(diagnostic.label)
                if columns and row.cell_len + 1 + cell_len(label) > columns:
                    # Past the edge the terminal broke the label mid-word
                    # ("n" / "o object has this id"): it goes on the next row,
                    # under the underline when it fits there.
                    lines.append(row)
                    row = gutter()
                    offset = underline_offset(shown, diagnostic.column)
                    if row.cell_len + 1 + cell_len(offset) + cell_len(label) > columns:
                        offset = ""
                    row.append(" " + offset)
                    row.append(label, style=style)
                else:
                    row.append(" " + label, style=style)
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
        lead = row.cell_len + 1
        row.append(" " + safe(text))
        if not columns:
            lines.append(row)
            continue
        # Continuation lines keep the frame's bar and start under the text.
        indent = Text(pad)
        indent.append(" " if last else bar, style=_GUTTER_STYLE)
        indent.append(" " * (lead - indent.cell_len))
        lines.extend(wrap_text(row, columns, indent))
    return lines


class QueryHighlighter:
    """The engine's highlight tokens for each file a frame shows, read once per file.

    Callable as :data:`LineStyles`. A file the engine cannot read, or a run
    whose engine does not load, is shown without colour: highlighting never
    fails a command.
    """

    def __init__(self) -> None:
        self._files: dict[Path, dict[int, list[tuple[int, int, str]]]] = {}

    def __call__(self, path: Path, line: int) -> list[tuple[int, int, str]]:
        if path not in self._files:
            self._files[path] = self._read(path)
        return self._files[path].get(line, [])

    @staticmethod
    def _read(path: Path) -> dict[int, list[tuple[int, int, str]]]:
        from opentide.analysis import EngineUnavailableError, highlight, language_for_path

        by_line: dict[int, list[tuple[int, int, str]]] = {}
        try:
            language = language_for_path(path)
            if language is None:
                return by_line
            tokens = highlight(path.read_text(encoding="utf-8"), language)
        except (EngineUnavailableError, OSError, UnicodeDecodeError, ValueError):
            return by_line
        for token in tokens:
            style = QUERY_STYLES.get(token.capture)
            if style is None or token.end_line != token.line:
                continue
            # Text positions: 1-based code points → 0-based offsets after the
            # leading space the source row starts with.
            by_line.setdefault(token.line, []).append((token.column, token.end_column, style))
        return by_line


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
    # Only a terminal wraps a long line, and it breaks wherever the edge falls.
    columns = console.width if console.is_terminal else None
    # Colour, so a person at a terminal only: plain output stays plain.
    styles = QueryHighlighter() if mode is OutputMode.HUMAN else None
    for diagnostic in sort_diagnostics(shown):
        for line in diagnostic_lines(
            diagnostic,
            sources=sources,
            encoding=encoding,
            cwd=cwd,
            links=mode is OutputMode.HUMAN,
            columns=columns,
            styles=styles,
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
