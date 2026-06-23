"""Markdown link helpers."""

from __future__ import annotations

import re

from opentide.documentation.format.protocol import MarkdownFormatter


def slugify(name: str) -> str:
    """Create a filesystem-safe slug from an object name."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name.strip()).strip("-").lower()
    return slug or "object"


def wiki_target(*, folder: str, slug: str) -> str:
    """Build a markdown target for object pages."""
    return f"{folder}/{slug}.md"


def render_link(formatter: MarkdownFormatter, text: str, target: str, *, wiki: bool = False) -> str:
    """Render a normal or wiki-formatted link."""
    if wiki:
        return formatter.wiki_link(text, target)
    return formatter.link(text, target)
