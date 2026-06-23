"""Markdown formatter protocol and defaults."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol


class MarkdownFormatter(Protocol):
    """Flavor-specific markdown formatting hooks."""

    flavor: str

    def heading(self, level: int, text: str) -> str: ...

    def paragraph(self, text: str) -> str: ...

    def code_block(self, language: str, body: str) -> str: ...

    def fold(self, summary: str, body: str) -> str: ...

    def link(self, text: str, target: str, title: str | None = None) -> str: ...

    def wiki_link(self, text: str, target: str) -> str: ...

    def table(self, headers: list[str], rows: list[list[str]]) -> str: ...

    def index_table(self, headers: list[str], rows: list[list[str]]) -> str: ...

    def strike(self, text: str) -> str: ...

    def frontmatter(self, title: str, **meta: str) -> str: ...

    def mermaid_fence(self, diagram: str) -> str: ...

    def table_of_contents(self) -> str: ...

    def page_filename(self, slug: str, uuid: str | None) -> str: ...

    def diagram_relations_type(self) -> Literal["mindmap", "flowchart", "graph"]: ...

    def diagram_chaining_type(self) -> Literal["flowchart", "graph"]: ...

    def diagram_supports_subgraphs(self) -> bool: ...

    def diagram_flowchart(self, diagram: str) -> str: ...

    def diagram_mindmap(self, diagram: str) -> str: ...


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
        header = "| " + " | ".join(headers) + " |"
        sep = "| " + " | ".join("---" for _ in headers) + " |"
        body = ["| " + " | ".join(row) + " |" for row in rows]
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

    def diagram_relations_type(self) -> Literal["mindmap", "flowchart", "graph"]:
        return "flowchart"

    def diagram_chaining_type(self) -> Literal["flowchart", "graph"]:
        return "flowchart"

    def diagram_supports_subgraphs(self) -> bool:
        return True

    def diagram_flowchart(self, diagram: str) -> str:
        return diagram

    def diagram_mindmap(self, diagram: str) -> str:
        return diagram
