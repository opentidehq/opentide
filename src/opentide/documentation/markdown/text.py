"""Text helpers shared by every documentation section.

Values reach a page from YAML, vocabularies and platform models. These helpers
turn them into Markdown that renders the same on every flavor: no Python
reprs, no raw newlines inside table cells, no unescaped pipes.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from enum import Enum

#: ATT&CK descriptions cite their sources inline: ``(Citation: OPM Leak)``.
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
#: The end of a sentence: punctuation followed by whitespace and a capital or a link.
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z\[(])")
#: Neither ``e.g.`` nor ``i.e.`` ends a sentence.
_ABBREVIATION = re.compile(r"\b(?:e\.g|i\.e|etc|vs|ex)\.$", re.IGNORECASE)


def table_cell(value: str) -> str:
    """One table cell: a newline would end the row, an unescaped pipe the cell."""
    collapsed = " ".join(value.split())
    return re.sub(r"(?<!\\)\|", r"\\|", collapsed) or "-"


def inline_code(value: object) -> str:
    """*value* as a code span, widening the fence when the text holds backticks."""
    text = " ".join(stringify(value).split())
    if not text:
        return ""
    fence = "`"
    while fence in text:
        fence += "`"
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def stringify(value: object) -> str:
    """A value, or a collection of values, as text, never as a Python repr.

    Booleans are written as YAML writes them (``true``), the spelling authors
    use in the object files.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Enum):
        return stringify(value.value)
    if isinstance(value, str):
        return value
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
        items = [text for item in value if (text := stringify(item))]
        if isinstance(value, (set, frozenset)):
            items.sort()
        return ", ".join(items)
    return str(value)


def strip_citations(text: str) -> str:
    """Drop ATT&CK's inline ``(Citation: ...)`` markers."""
    return _CITATION.sub("", text)


def first_sentence(text: str, *, limit: int = 240) -> str:
    """The opening sentence of *text*, citations removed, at most *limit* characters."""
    collapsed = " ".join(strip_citations(text).split())
    if not collapsed:
        return ""
    for match in _SENTENCE_END.finditer(collapsed):
        candidate = collapsed[: match.start()]
        if _ABBREVIATION.search(candidate):
            continue
        return truncate(candidate, limit)
    return truncate(collapsed, limit)


def truncate(text: str, limit: int) -> str:
    """Collapse whitespace and cut *text* at *limit* characters, on a word boundary."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    cut = collapsed[: limit - 1]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:") + "…"


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    """``1 rule`` / ``3 rules``."""
    word = singular if count == 1 else (plural_form or f"{singular}s")
    return f"{count} {word}"


def join_lines(values: Iterable[str]) -> str:
    """Values one per line inside a table cell."""
    return "<br>".join(value for value in values if value)
