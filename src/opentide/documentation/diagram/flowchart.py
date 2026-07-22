"""Flowchart diagram rendering."""

from __future__ import annotations

from opentide.documentation.diagram.graph import Edge, Node
from opentide.documentation.diagram.sanitize import sanitize_label
from opentide.documentation.format.protocol import MarkdownFormatter


def build_flowchart(
    formatter: MarkdownFormatter,
    *,
    nodes: list[Node],
    edges: list[Edge],
    direction: str = "TD",
    diagram_type: str | None = None,
    subgraphs: dict[str, list[str]] | None = None,
) -> str:
    """Build a mermaid flowchart body and apply flavor hooks."""
    kind = diagram_type or formatter.diagram_chaining_type()
    lines = [f"{kind} {direction}"]
    unique_nodes = {node.identifier: node for node in nodes}

    grouped_ids: set[str] = set()
    if subgraphs:
        for title, node_ids in subgraphs.items():
            members = [node_id for node_id in node_ids if node_id in unique_nodes]
            if not members:
                continue
            lines.append(f'subgraph "{sanitize_label(title)}"')
            for node_id in members:
                lines.append(unique_nodes[node_id].render())
                grouped_ids.add(node_id)
            lines.append("end")

    for node in unique_nodes.values():
        if node.identifier not in grouped_ids:
            lines.append(node.render())
    lines.extend(edge.render() for edge in edges)
    diagram = "\n".join(lines)
    return formatter.mermaid_fence(formatter.diagram_flowchart(diagram))
