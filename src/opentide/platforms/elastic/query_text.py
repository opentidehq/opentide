"""Read ES|QL and EQL query text past its comments and string literals.

Regexes run over a *masked* copy of the query: comments and the contents of
string literals and backquoted identifiers are replaced with spaces, newlines
kept, so every offset still points at the same character in the original.
"""

from __future__ import annotations

import re

_SOURCE_COMMAND = re.compile(r"(?i)\s*(?:FROM|TS)\b")
_METADATA = re.compile(r"(?i)\bMETADATA\b")
_METADATA_ID = re.compile(r"(?i)\bMETADATA\b[^|]*\b_id\b")
_STATS_STEP = re.compile(r"(?i)\s*STATS\b")
_EQL_SEQUENCE = re.compile(r"(?i)\s*sequence\b")
_EQL_MAXSPAN = re.compile(r"(?i)\bmaxspan\s*=\s*((\d+)\s*(ms|s|m|h|d))\b")
_UNIT_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


def _block_comment_end(text: str, start: int, *, nested: bool) -> int:
    depth, i = 1, start + 2
    while i < len(text) and depth:
        if nested and text.startswith("/*", i):
            depth, i = depth + 1, i + 2
        elif text.startswith("*/", i):
            depth, i = depth - 1, i + 2
        else:
            i += 1
    return i


def _closing(text: str, start: int, quote: str) -> tuple[int, int]:
    """``(content_end, literal_end)`` of the literal opened at ``start``."""
    i = start + 1
    while i < len(text):
        char = text[i]
        if quote == '"' and char == "\\":
            i += 2
        elif char == quote:
            if quote == "`" and text.startswith("``", i):
                i += 2
                continue
            return i, i + 1
        else:
            i += 1
    return len(text), len(text)


def mask_query(text: str, *, nested_comments: bool, keep_strings: bool = False) -> str:
    """Blank comments and literal contents, keeping offsets and newlines.

    Comments are ``//`` to end of line and ``/* */`` (nested when
    ``nested_comments``, as in ES|QL and EQL). Literals are double-quoted strings with
    backslash escapes, raw triple-quoted strings, and backquoted identifiers
    (a doubled backquote escapes one). Their delimiters stay; their contents
    are blanked unless ``keep_strings``.
    """
    out = list(text)

    def blank(start: int, end: int) -> None:
        for k in range(start, end):
            if out[k] not in "\r\n":
                out[k] = " "

    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end == -1 else end
            blank(i, end)
        elif text.startswith("/*", i):
            end = _block_comment_end(text, i, nested=nested_comments)
            blank(i, end)
        elif text.startswith('"""', i):
            close = text.find('"""', i + 3)
            content_end = len(text) if close == -1 else close
            end = min(len(text), content_end + 3)
            while end < len(text) and end < content_end + 5 and text[end] == '"':
                end += 1
            if not keep_strings:
                blank(i + 3, content_end)
        elif text[i] in '"`':
            content_end, end = _closing(text, i, text[i])
            if not keep_strings:
                blank(i + 1, content_end)
        else:
            i += 1
            continue
        i = end
    return "".join(out)


def esql_sources(query: str) -> str:
    """Comma-joined sources of the ``FROM`` or ``TS`` source command.

    Sources run up to the first pipe or ``METADATA``; quotes are stripped and
    ``cluster:`` prefixes and ``::`` selectors are kept as written.
    """
    masked = mask_query(query, nested_comments=True)
    plain = mask_query(query, nested_comments=True, keep_strings=True)
    pipe = masked.find("|")
    end = len(masked) if pipe == -1 else pipe
    command = _SOURCE_COMMAND.match(masked, 0, end)
    if not command:
        return ""
    metadata = _METADATA.search(masked, command.end(), end)
    head = plain[command.end() : metadata.start() if metadata else end]
    parts = (raw.strip().strip("\"'`") for raw in head.split(","))
    return ",".join(part for part in parts if part)


def esql_aggregates(query: str) -> bool:
    """True when a pipeline step is ``STATS`` (``INLINE STATS`` keeps rows)."""
    masked = mask_query(query, nested_comments=True)
    return any(_STATS_STEP.match(step) for step in masked.split("|"))


def esql_has_metadata_id(query: str) -> bool:
    """True when the query requests ``METADATA _id`` outside comments and strings."""
    return bool(_METADATA_ID.search(mask_query(query, nested_comments=True)))


def eql_is_sequence(query: str) -> bool:
    """True when the EQL query is a ``sequence``."""
    return bool(_EQL_SEQUENCE.match(mask_query(query, nested_comments=True)))


def eql_maxspans(query: str) -> list[tuple[str, int]]:
    """Every ``maxspan=`` in the EQL query as ``(text, milliseconds)``."""
    masked = mask_query(query, nested_comments=True)
    return [
        (match.group(1), int(match.group(2)) * _UNIT_MS[match.group(3).lower()])
        for match in _EQL_MAXSPAN.finditer(masked)
    ]
