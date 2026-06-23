"""Filesystem writer for documentation pages."""

from __future__ import annotations

from pathlib import Path


def write_page(path: Path, content: str) -> None:
    """Write markdown content to disk, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")
