"""High-level diagram builders wired to catalog relations."""

from typing import Literal

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.diagram.flowchart import build_flowchart
from opentide.documentation.diagram.graph import Edge, Node
from opentide.documentation.diagram.mindmap import build_mindmap
from opentide.documentation.format.protocol import MarkdownFormatter


def render_relations_diagram(
    formatter: MarkdownFormatter,
    catalog: DocumentationCatalog,
    *,
    uuid: str,
    name: str,
    direction: Literal["upstream", "downstream", "both"] = "both",
) -> str:
    """Render relations diagram for an object using catalog lookups."""
    related = catalog.related_entries(uuid, direction=direction)
    if not related:
        return ""

    rel_type = formatter.diagram_relations_type()
    if rel_type == "mindmap":
        branches: dict[str, list[str]] = {}
        for entry in related:
            label = catalog.resolve_name(entry.uuid)
            branches.setdefault(label, [])
        return build_mindmap(formatter, name, branches)

    nodes = [Node(uuid, name)]
    edges: list[Edge] = []
    subgraphs: dict[str, list[str]] = {}
    for entry in related:
        label = catalog.resolve_name(entry.uuid)
        nodes.append(Node(entry.uuid, label))
        edges.append(Edge(uuid, entry.uuid, label=entry.relation))
        if entry.relation:
            subgraphs.setdefault(entry.relation.title(), []).append(entry.uuid)
    return build_flowchart(
        formatter,
        nodes=nodes,
        edges=edges,
        direction="TB",
        diagram_type=rel_type,
        subgraphs=subgraphs if formatter.diagram_supports_subgraphs() else None,
    )


def render_chaining_diagram(
    formatter: MarkdownFormatter,
    catalog: DocumentationCatalog,
    *,
    uuid: str,
    name: str,
) -> str:
    """Render threat chaining flowchart (no subgraphs on Azure DevOps)."""
    chain = catalog.chaining_entries(uuid)
    if not chain:
        return ""

    nodes = [Node(uuid, name)]
    edges: list[Edge] = []
    previous = uuid
    for entry in chain:
        label = catalog.resolve_name(entry.uuid)
        nodes.append(Node(entry.uuid, label))
        edges.append(Edge(previous, entry.uuid, label=entry.relation))
        previous = entry.uuid
    return build_flowchart(
        formatter,
        nodes=nodes,
        edges=edges,
        direction="LR",
        diagram_type=formatter.diagram_chaining_type(),
    )
