"""Generic markdown formatter."""

from __future__ import annotations

from dataclasses import dataclass

from opentide.documentation.format.protocol import BaseFormatter


@dataclass(frozen=True)
class GenericFormatter(BaseFormatter):
    """Formatter for markdown targets without special syntax."""

    flavor: str = "generic"

    def page_filename(self, slug: str, uuid: str | None) -> str:
        return f"{slug}.md"
