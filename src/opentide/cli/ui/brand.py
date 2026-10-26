"""The opentide marks for the terminal, drawn from ``opentidehq/.github/assets``.

Three marks, stored as pixel grids and drawn with upper half-blocks (two pixel
rows per terminal row):

| Mark           | Cells   | Where                                            |
|----------------|---------|--------------------------------------------------|
| :data:`LOGO`   | 80 × 10 | the ``setup`` wizard welcome                     |
| :data:`ICON`   | 28 × 14 | the home screen of a bare ``opentide``           |
| :func:`pill`   | 1 line  | section headers, and terminals too narrow for the logo |

Rules (``docs/internal/cli-experience.md``, "Brand in the terminal"): marks
draw only in ``human`` mode and only when the stream can encode the block
characters; otherwise nothing is drawn. Reflex Blue is a fill, never a text
colour. Without colour the shapes stay: the disc is drawn in the terminal's
own foreground with the glyph cut out.

The grids were rasterised once from ``assets/svg/icon-normal.svg`` and
``logo-normal.svg`` (8× supersampled, majority vote) and are kept here as
strings, so nothing is rasterised at run time.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from rich.console import Console
from rich.style import Style
from rich.text import Text

from opentide.cli.ui.glyphs import can_encode
from opentide.cli.ui.mode import OutputMode, get_mode

#: Pantone Reflex Blue, from ``opentidehq/.github/assets/README.md``.
BLUE = "#001489"
WHITE = "#ffffff"

#: Said wherever the product describes itself.
TAGLINE = "Spec-driven development for agentic detection engineering"

# The Material "Tsunami" glyph on its circle: outer crest, inner arc, the curl
# into the tail, and two rippled wave lines. ``B`` disc, ``W`` glyph.
ICON: tuple[str, ...] = (
    "..........BBBBBBBB..........",
    "........BBBBBBBBBBBB........",
    "......BBBBBBBBBBBBBBBB......",
    ".....BBBBBBBBBBBBBBBBBB.....",
    "....BBBBBBBBBBBBBBBBBBBB....",
    "...BBBBBBBBBBBBBBBBBBBBBB...",
    "..BBBBBBBBBBWWWWWWWBBBBBBB..",
    "..BBBBBBBBWWWWWWWWBBBBBBBB..",
    ".BBBBBBBWWWWWWWBWWBBBBBBBBB.",
    ".BBBBBBWWWBWWBBBWWBBBBBBBBB.",
    "BBBBBBBWWBBWWBBBWWBBBBBBBBBB",
    "BBBBBBWWBBWWBBBBWWWBBBBBBBBB",
    "BBBBBWWWBBWWBBBBBWWWWWWBBBBB",
    "BBBBBWWBBBWWBBBBBBWWWWWBBBBB",
    "BBBBBWWBBBWWWBBBBBBBBBBBBBBB",
    "BBBBBWWWWBBWWWWBBBBWWBBBBBBB",
    "BBBBBWWWWWWWWWWWWWWWWWWBBBBB",
    "BBBBBWWWWWWWWWWWWWWWWWWBBBBB",
    ".BBBBBBBBBBBBBBBBBBBBBBBBBB.",
    ".BBBBBBWWBBBBWWBBBBWWBBBBBB.",
    "..BBBWWWWWWWWWWWWWWWWWWBBB..",
    "..BBBWWWWWWWWWWWWWWWWWWBBB..",
    "...BBBBBBBBBBBBBBBBBBBBBB...",
    "....BBBBBBBBBBBBBBBBBBBB....",
    ".....BBBBBBBBBBBBBBBBBB.....",
    "......BBBBBBBBBBBBBBBB......",
    "........BBBBBBBBBBBB........",
    "..........BBBBBBBB..........",
)

# logo-normal: the Reflex Blue pill; a white circle holding the 16 px blue
# Tsunami glyph; the lower-case wordmark with 2 px stems, after Inter SemiBold.
# ``B`` blue, ``W`` white.
LOGO: tuple[str, ...] = (
    ".......BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.......",
    ".....BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.....",
    "...BBBBWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB...",
    "..BBBWWWWWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB..",
    "..BBWWWWWWWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBWWBBBBBBBBBBBBBB..",
    ".BBWWWWWWBBBWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBWWBBWWBBBBBWWBBBBBBBBBBBBBBB.",
    ".BBWWWWBBBBBWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBWWBBBBBBBBBWWBBBBBBBBBBBBBBB.",
    "BBWWWWBBBBWBWWWWWWBBBBBWWWWBBWWWWWBBBWWWWBBWWWWWBBWWWWBWWBBWWWWWBBWWWWBBBBBBBBBB",
    "BBWWWBBWBWWBBWWWWWBBBBWWBBWWBWWBBWWBWWBBWWBWWBBWWBBWWBBWWBWWBBWWBWWBBWWBBBBBBBBB",
    "BBWWWBWWBWWWBBBWWWBBBBWWBBWWBWWBBWWBWWWWWWBWWBBWWBBWWBBWWBWWBBWWBWWWWWWBBBBBBBBB",
    "BBWWWBWWBBWWWWWWWWBBBBWWBBWWBWWBBWWBWWBBBBBWWBBWWBBWWBBWWBWWBBWWBWWBBBBBBBBBBBBB",
    "BBWWWBBBBBBBBBBWWWBBBBWWBBWWBWWBBWWBWWBBWWBWWBBWWBBWWBBWWBWWBBWWBWWBBWWBBBBBBBBB",
    "BBWWWWWWWWWWWWWWWWBBBBBWWWWBBWWWWWBBBWWWWBBWWBBWWBBBWWBWWBBWWWWWBBWWWWBBBBBBBBBB",
    ".BBWWBBBBBBBBBBWWBBBBBBBBBBBBWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.",
    ".BBWWWWWWWWWWWWWWBBBBBBBBBBBBWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.",
    "..BBWWWWWWWWWWWWBBBBBBBBBBBBBWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB..",
    "..BBBWWWWWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB..",
    "...BBBBWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB...",
    ".....BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.....",
    ".......BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.......",
)

#: Pixel → colour. ``.`` is the terminal's own background.
PALETTE: Mapping[str, str | None] = {"B": BLUE, "W": WHITE, ".": None}

#: Characters a mark is drawn with; a stream that cannot encode them gets none.
BLOCKS = "▀▄█▐▌≋"

#: Terminal columns the logo needs, with its two-column indent.
LOGO_MIN_WIDTH = len(LOGO[0]) + 2

_MONO_CELLS = {(True, True): "█", (True, False): "▀", (False, True): "▄", (False, False): " "}


def can_draw(console: Console, *, mode: OutputMode | None = None) -> bool:
    """Whether *console* may show a mark: ``human`` mode and an encoding with the blocks."""
    if (mode or get_mode()) is not OutputMode.HUMAN:
        return False
    return can_encode(BLOCKS, encoding=console.encoding or "utf-8")


def is_mono(console: Console) -> bool:
    """Whether *console* prints without colour (``NO_COLOR``, a dumb terminal)."""
    return console.no_color or console.color_system is None


def render(
    rows: Sequence[str],
    palette: Mapping[str, str | None] = PALETTE,
    *,
    mono: bool = False,
    ink: str = "B",
) -> Text:
    """Draw a pixel grid with upper half-blocks, two pixel rows per line.

    In colour, each cell takes the top pixel as foreground and the bottom one
    as background. *mono* draws the *ink* pixels in the terminal's foreground
    and leaves every other pixel blank, which keeps the shape without colour.
    """
    grid = list(rows)
    if len(grid) % 2:
        grid.append("." * len(grid[0]))
    text = Text(no_wrap=True, overflow="crop")
    for y in range(0, len(grid), 2):
        if y:
            text.append("\n")
        for top, bottom in zip(grid[y], grid[y + 1], strict=True):
            if mono:
                text.append(_MONO_CELLS[(top in ink, bottom in ink)])
                continue
            upper, lower = palette[top], palette[bottom]
            if upper is None and lower is None:
                text.append(" ")
            elif upper is None:
                text.append("▄", Style(color=lower))
            elif lower is None or upper == lower:
                text.append("█" if upper == lower else "▀", Style(color=upper))
            else:
                text.append("▀", Style(color=upper, bgcolor=lower))
    return text


def icon(*, mono: bool = False) -> Text:
    """The 28 × 14 icon: a Reflex Blue disc holding the white Tsunami glyph."""
    return render(ICON, mono=mono)


def logo(*, mono: bool = False) -> Text:
    """The 80 × 10 pill logo: icon circle and ``opentide`` on Reflex Blue."""
    return render(LOGO, mono=mono)


def pill(*, mono: bool = False, encoding: str = "utf-8") -> Text:
    """``▐ ≋ opentide ▌``: white on a Reflex Blue pill, for one-line headers.

    Without colour the pill is drawn in reverse video. A stream that cannot
    encode the caps gets the bare word.
    """
    if not can_encode(BLOCKS, encoding=encoding):
        return Text("opentide", style="bold")
    if mono:
        return Text.assemble("▐", (" ≋ opentide ", Style(reverse=True, bold=True)), "▌")
    return Text.assemble(
        ("▐", Style(color=BLUE)),
        (" ≋ opentide ", Style(color=WHITE, bgcolor=BLUE, bold=True)),
        ("▌", Style(color=BLUE)),
    )


def header(label: str, *, mono: bool = False, encoding: str = "utf-8") -> Text:
    """A section header: `` ≋ `` on a blue square, then *label* in bold."""
    if not can_encode(BLOCKS, encoding=encoding):
        return Text(label, style="bold")
    mark = Style(reverse=True, bold=True) if mono else Style(color=WHITE, bgcolor=BLUE, bold=True)
    return Text.assemble((" ≋ ", mark), " ", (label, "bold"))
