"""Status glyphs, with an ASCII fallback for streams that cannot encode them.

Looked up by name so a renderer never hard-codes a character: a Windows console
on cp1252, or a pipe opened with ``PYTHONIOENCODING=ascii``, gets the fallback
instead of a ``UnicodeEncodeError`` or a ``?``.
"""

from __future__ import annotations

import codecs
import sys
from typing import NamedTuple, TextIO


class Glyph(NamedTuple):
    symbol: str
    fallback: str


#: Name → glyph. See "Human output grammar" in ``docs/internal/cli-experience.md``.
GLYPHS: dict[str, Glyph] = {
    "ok": Glyph("✓", "ok"),
    "failed": Glyph("✗", "x"),
    "warning": Glyph("!", "!"),
    "create": Glyph("+", "+"),
    "update": Glyph("~", "~"),
    "disable": Glyph("-", "-"),
    "delete": Glyph("×", "x"),
    "next": Glyph("→", "->"),
    "separator": Glyph("·", "-"),
    "mark": Glyph("≋", "opentide"),
}


def can_encode(text: str, stream: TextIO | None = None, *, encoding: str | None = None) -> bool:
    """Whether *text* survives the encoding of *stream* (stdout by default)."""
    if encoding is None:
        target = sys.stdout if stream is None else stream
        encoding = getattr(target, "encoding", None) or "utf-8"
    try:
        codecs.lookup(encoding)
        text.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def glyph(name: str, stream: TextIO | None = None, *, encoding: str | None = None) -> str:
    """The glyph called *name*, or its fallback when the stream cannot encode it.

    Raises ``KeyError`` for an unknown name, so a typo fails a test rather than
    printing nothing.
    """
    entry = GLYPHS[name]
    return entry.symbol if can_encode(entry.symbol, stream, encoding=encoding) else entry.fallback
