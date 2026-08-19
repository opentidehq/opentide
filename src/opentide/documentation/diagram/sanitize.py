"""Mermaid string sanitization utilities."""

from __future__ import annotations

import re

_FORBIDDEN = str.maketrans({char: "" for char in "()[]{}|"})


def sanitize_identifier(value: str) -> str:
    """Normalize an identifier for mermaid node ids."""
    return re.sub(r"[^A-Za-z0-9_]", "_", value).strip("_") or "node"


def sanitize_label(value: str) -> str:
    """Normalize labels for mermaid display."""
    cleaned = value.translate(_FORBIDDEN).replace('"', "'").replace("\n", " ").strip()
    return cleaned or "node"


def wrap_label(value: str, limit: int = 24) -> str:
    """Wrap a mermaid label with ``<br>`` so long names stay readable."""
    cleaned = sanitize_label(value)
    words = cleaned.split()
    if not words:
        return cleaned
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= limit:
            current = candidate
            continue
        lines.append(current)
        current = word
    lines.append(current)
    return "<br>".join(lines)
