"""Azure DevOps markdown formatter."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

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

    def diagram_relations_type(self) -> Literal["mindmap", "flowchart", "graph"]:
        return "graph"

    def diagram_chaining_type(self) -> Literal["flowchart", "graph"]:
        return "graph"

    def diagram_supports_subgraphs(self) -> bool:
        return False

    def diagram_flowchart(self, diagram: str) -> str:
        # Microsoft docs: flowchart keyword and long arrows may fail at render time.
        downgraded = diagram.replace("flowchart", "graph", 1)
        return re.sub(r"-{4,}>", "-->", downgraded)

    def diagram_mindmap(self, diagram: str) -> str:
        return self.diagram_flowchart(diagram.replace("mindmap", "graph", 1))
