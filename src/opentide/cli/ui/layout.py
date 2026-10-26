"""Aligned columns without trailing blanks, for output that is read and diffed.

``Table.grid`` pads every cell to its column's width, so the last column of a
short row ends in spaces: noise in a CI log, a snapshot or a copied block.
:func:`columns` aligns the same way and trims each line.
"""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console, ConsoleOptions, RenderResult
from rich.text import Text


def columns(
    rows: Sequence[Sequence[Text | str]],
    *,
    gap: int = 2,
    indent: int = 0,
    right: Sequence[int] = (),
) -> Text:
    """*rows* as aligned columns, one line each; columns in *right* are right-aligned.

    Empty cells take no room: a column that is empty on every row disappears,
    and its gap with it.
    """
    cells = [[cell if isinstance(cell, Text) else Text(cell) for cell in row] for row in rows]
    count = max((len(row) for row in cells), default=0)
    widths = [
        max((row[i].cell_len for row in cells if i < len(row)), default=0) for i in range(count)
    ]
    text = Text()
    for number, row in enumerate(cells):
        if number:
            text.append("\n")
        line = Text(" " * indent)
        pending = ""
        for index, cell in enumerate(row):
            width = widths[index]
            if not width:
                continue
            line.append(pending)
            pad = " " * (width - cell.cell_len)
            if index in right:
                line.append(pad)
                line.append_text(cell)
                pending = " " * gap
            else:
                line.append_text(cell)
                pending = pad + " " * gap
        line.rstrip()
        text.append_text(line)
    return text


class Cropped:
    """*text* one terminal row per line: a line wider than the terminal ends in ``…``."""

    def __init__(self, text: Text) -> None:
        self.text = text

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = options.max_width
        for line in self.text.split("\n", allow_blank=True):
            line.truncate(width, overflow="ellipsis")
            yield line
