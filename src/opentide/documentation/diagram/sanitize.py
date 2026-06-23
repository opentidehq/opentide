"""Mermaid string sanitization utilities."""

from __future__ import annotations

import re


def sanitize_identifier(value: str) -> str:
    """Normalize an identifier for mermaid node ids."""
    return re.sub(r"[^A-Za-z0-9_]", "_", value).strip("_") or "node"


def sanitize_label(value: str) -> str:
    """Normalize labels for mermaid display."""
    return value.replace('"', "'").replace("\n", " ").strip()
