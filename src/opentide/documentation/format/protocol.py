"""Markdown formatter protocol and defaults."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Protocol

from opentide.documentation.diagram.mermaid import MermaidDialect

#: The callouts a page uses: a neutral aside, and something a reader must act on.
CalloutKind = Literal["note", "warning"]


class MarkdownFormatter(Protocol):
    """Flavor-specific markdown formatting hooks."""

    # Read-only: the formatters are frozen dataclasses.
    @property
    def flavor(self) -> str: ...

    def heading(self, level: int, text: str) -> str:
        pass

    def paragraph(self, text: str) -> str:
        pass

    def code_block(self, language: str, body: str) -> str:
        pass

    def fold(self, summary: str, body: str) -> str:
        pass

    def link(self, text: str, target: str, title: str | None = None) -> str:
        pass

    def wiki_link(self, text: str, target: str) -> str:
        pass

    def table(self, headers: list[str], rows: list[list[str]]) -> str:
        pass

    def index_table(self, headers: list[str], rows: list[list[str]]) -> str:
        pass

    def strike(self, text: str) -> str:
        pass

    def frontmatter(self, title: str, **meta: str) -> str:
        pass

    def mermaid_fence(self, diagram: str) -> str:
        pass

    def table_of_contents(self) -> str:
        pass

    def page_filename(self, slug: str, uuid: str | None) -> str:
        pass

    def heading_anchor(self, title: str) -> str:
        pass

    def mermaid_dialect(self) -> MermaidDialect:
        pass

    def callout(self, kind: CalloutKind, text: str) -> str:
        pass


@dataclass(frozen=True)
class BaseFormatter:
    """Cross-platform markdown defaults."""

    flavor: str = "generic"

    def heading(self, level: int, text: str) -> str:
        return "#" * max(level, 1) + " " + text + "\n"

    def paragraph(self, text: str) -> str:
        return text.strip() + "\n\n"

    def code_block(self, language: str, body: str) -> str:
        return f"```{language}\n{body}\n```\n\n"

    def fold(self, summary: str, body: str) -> str:
        return f"<details><summary>{summary}</summary>\n\n{body}\n\n</details>\n\n"

    def link(self, text: str, target: str, title: str | None = None) -> str:
        _ = title
        return f"[{text}]({target})"

    def wiki_link(self, text: str, target: str) -> str:
        return self.link(text, target)

    def table(self, headers: list[str], rows: list[list[str]]) -> str:
        header = "| " + " | ".join(_cell(text) for text in headers) + " |"
        sep = "| " + " | ".join("---" for _ in headers) + " |"
        body = ["| " + " | ".join(_cell(text) for text in row) + " |" for row in rows]
        return "\n".join([header, sep, *body]) + "\n"

    def index_table(self, headers: list[str], rows: list[list[str]]) -> str:
        return self.table(headers, rows)

    def strike(self, text: str) -> str:
        return f"~~{text}~~"

    def frontmatter(self, title: str, **meta: str) -> str:
        _ = meta
        return f"---\ntitle: {title}\n---\n\n"

    def mermaid_fence(self, diagram: str) -> str:
        return f"```mermaid\n{diagram}\n```\n"

    def table_of_contents(self) -> str:
        return ""

    def page_filename(self, slug: str, uuid: str | None) -> str:
        return f"{uuid or slug}.md"

    def heading_anchor(self, title: str) -> str:
        # Imported here: the links module imports this one.
        from opentide.documentation.markdown.links import heading_anchor

        return heading_anchor(title)

    def mermaid_dialect(self) -> MermaidDialect:
        # A CommonMark site's Mermaid version is unknown: no accessibility lines,
        # which a release before 9.4 refuses.
        return MermaidDialect(accessibility=False)

    def callout(self, kind: CalloutKind, text: str) -> str:
        """A highlighted aside. A plain blockquote, which every renderer shows."""
        return blockquote(f"**{kind.title()}:** {text.strip()}")


# A ``|`` that is not already escaped, so cells built with ``_table_cell`` are
# not escaped twice.
_BARE_PIPE = re.compile(r"(?<!\\)\|")


def _cell(text: str) -> str:
    """One table cell: a pipe or a line break would end the cell or the row."""
    return _BARE_PIPE.sub(r"\\|", " ".join(text.splitlines()))


def blockquote(text: str) -> str:
    """*text* as a blockquote, every line prefixed so paragraphs stay inside it."""
    lines = text.strip().splitlines() or [""]
    return "\n".join(f"> {line}".rstrip() for line in lines) + "\n\n"
