"""Azure DevOps markdown formatter."""

from __future__ import annotations

from dataclasses import dataclass

from opentide.documentation.diagram.mermaid import MermaidDialect
from opentide.documentation.format.protocol import BaseFormatter


@dataclass(frozen=True)
class AzureDevOpsFormatter(BaseFormatter):
    """Formatter for Azure DevOps wiki markdown rendering."""

    flavor: str = "azure_devops"

    def fold(self, summary: str, body: str) -> str:
        return f"<details><summary>{summary}</summary>\n\n\n{body}\n\n</details>\n\n"

    def table_of_contents(self) -> str:
        return "[[_TOC_]]\n"

    def mermaid_fence(self, diagram: str) -> str:
        return f"::: mermaid\n{diagram}\n:::\n"

    def wiki_link(self, text: str, target: str) -> str:
        page = target.replace(".md", "").split("/")[-1]
        return self.link(text, f"/{page}")

    def page_filename(self, slug: str, uuid: str | None) -> str:
        safe = slug.replace(" ", "-")
        return f"{safe}.md"

    def mermaid_dialect(self) -> MermaidDialect:
        # The wiki's Mermaid release fails a whole diagram on the `flowchart`
        # keyword, on subgraphs and on styles; shapes and the legend still
        # carry every node's kind.
        return MermaidDialect(keyword="graph", lanes=False, styles=False, accessibility=False)
