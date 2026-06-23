"""GitHub markdown formatter."""

from __future__ import annotations

from dataclasses import dataclass

from opentide.documentation.format.protocol import BaseFormatter


@dataclass(frozen=True)
class GitHubFormatter(BaseFormatter):
    """Formatter for GitHub markdown rendering."""

    flavor: str = "github"

    def page_filename(self, slug: str, uuid: str | None) -> str:
        return f"{slug}.md"
