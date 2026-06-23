"""Flowchart diagram rendering."""

from __future__ import annotations

from opentide.documentation.diagram.graph import Edge, Node
from opentide.documentation.format.protocol import MarkdownFormatter


def build_flowchart(
    formatter: MarkdownFormatter,
    *,
    nodes: list[Node],
    edges: list[Edge],
    direction: str = "TD",
    diagram_type: str | None = None,
) -> str:
    """Build a mermaid flowchart body and apply flavor hooks."""
    kind = diagram_type or formatter.diagram_chaining_type()
    lines = [f"{kind} {direction}"]
    lines.extend(node.render() for node in nodes)
    lines.extend(edge.render() for edge in edges)
    diagram = "\n".join(lines)
    return formatter.mermaid_fence(formatter.diagram_flowchart(diagram))
