"""GitHub markdown formatter."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from opentide.documentation.diagram.mermaid import MermaidDialect
from opentide.documentation.format.protocol import BaseFormatter, CalloutKind, blockquote


@dataclass(frozen=True)
class GitHubFormatter(BaseFormatter):
    """Formatter for GitHub markdown rendering."""

    flavor: str = "github"

    def page_filename(self, slug: str, uuid: str | None) -> str:
        return f"{slug}.md"

    def mermaid_dialect(self) -> MermaidDialect:
        return MermaidDialect()

    def callout(self, kind: CalloutKind, text: str) -> str:
        """A GitHub alert (``> [!NOTE]``), rendered as a coloured, titled box."""
        return blockquote(f"[!{kind.upper()}]\n{text.strip()}")

    def heading_anchor(self, title: str) -> str:
        """The id GitHub gives a heading (github-slugger, without duplicate suffixes).

        Lowercase, drop punctuation and symbols other than ``-`` and ``_``, and
        turn each space into ``-`` without collapsing runs.
        """
        kept = "".join(char for char in title.strip().lower() if _anchor_char(char))
        return kept.replace(" ", "-")


def _anchor_char(char: str) -> bool:
    return char in " -_" or unicodedata.category(char)[0] in {"L", "M", "N"}
