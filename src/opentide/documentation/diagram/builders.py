"""High-level diagram builders wired to catalog relations."""

from __future__ import annotations

from typing import Literal

from opentide.documentation.catalog import (
    CoverageGraph,
    CoverageNode,
    DocumentationCatalog,
)
from opentide.documentation.diagram.flowchart import build_flowchart
from opentide.documentation.diagram.graph import Edge, Node, NodeShape
from opentide.documentation.diagram.mindmap import build_mindmap
from opentide.documentation.format.protocol import MarkdownFormatter

_SHAPE_BY_TYPE: dict[str, NodeShape] = {
    "threat": "hex",
    "objective": "stadium",
    "rule": "rect",
    "signal": "circle",
}

_SUBGRAPH_BY_TYPE = {
    "threat": "Threats",
    "objective": "Objectives",
    "rule": "Rules",
    "signal": "Signals",
}


def render_coverage_diagram(
    formatter: MarkdownFormatter,
    graph: object,
    *,
    current_uuid: str,
) -> str:
    """Render a typed coverage flowchart; no-op for empty or mock graphs."""
    if not isinstance(graph, CoverageGraph) or graph.is_empty():
        return ""
    return _render_typed_graph(
        formatter,
        graph,
        current_uuid=current_uuid,
        direction="TB",
        diagram_type=formatter.diagram_relations_type(),
        group_by="object_type",
    )


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
    if not isinstance(related, list) or not related:
        return ""

    rel_type = formatter.diagram_relations_type()
    if rel_type == "mindmap":
        branches: dict[str, list[str]] = {}
        for entry in related:
            label = catalog.resolve_name(entry.uuid)
            branches.setdefault(label, [])
        return build_mindmap(formatter, name, branches)

    nodes = [Node(uuid, name, shape=_shape_for(None))]
    edges: list[Edge] = []
    subgraphs: dict[str, list[str]] = {}
    for entry in related:
        object_type = entry.object_type or entry.relation or "object"
        label = entry.name or catalog.resolve_name(entry.uuid)
        nodes.append(Node(entry.uuid, label, shape=_shape_for(object_type)))
        if entry.direction == "upstream":
            edges.append(Edge(entry.uuid, uuid, label=entry.relation))
        else:
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
    network = catalog.chaining_network(uuid)
    if isinstance(network, CoverageGraph) and not network.is_empty():
        return _render_typed_graph(
            formatter,
            network,
            current_uuid=uuid,
            direction="LR",
            diagram_type=formatter.diagram_chaining_type(),
            group_by="killchain",
        )

    chain = catalog.chaining_entries(uuid)
    if not isinstance(chain, list) or not chain:
        return ""

    nodes = [Node(uuid, name, shape="hex")]
    edges: list[Edge] = []
    previous = uuid
    for entry in chain:
        label = entry.name or catalog.resolve_name(entry.uuid)
        nodes.append(Node(entry.uuid, label, shape="hex"))
        edges.append(Edge(previous, entry.uuid, label=entry.relation))
        previous = entry.uuid
    return build_flowchart(
        formatter,
        nodes=nodes,
        edges=edges,
        direction="LR",
        diagram_type=formatter.diagram_chaining_type(),
    )


def _render_typed_graph(
    formatter: MarkdownFormatter,
    graph: CoverageGraph,
    *,
    current_uuid: str,
    direction: str,
    diagram_type: str,
    group_by: Literal["object_type", "killchain"],
) -> str:
    nodes = [
        Node(node.uuid, node.name, shape=_shape_for(node.object_type)) for node in graph.nodes
    ]
    edges = [
        Edge(
            edge.source,
            edge.target,
            label=edge.label,
            bidirectional=edge.arrow == "bidirectional",
        )
        for edge in graph.edges
    ]
    subgraphs: dict[str, list[str]] | None = None
    if formatter.diagram_supports_subgraphs():
        grouped: dict[str, list[str]] = {}
        for node in graph.nodes:
            if node.uuid == current_uuid and group_by == "object_type":
                continue
            title = _group_title(node, group_by)
            if not title:
                continue
            grouped.setdefault(title, []).append(node.uuid)
        subgraphs = grouped or None
    return build_flowchart(
        formatter,
        nodes=nodes,
        edges=edges,
        direction=direction,
        diagram_type=diagram_type,
        subgraphs=subgraphs,
    )


def _shape_for(object_type: str | None) -> NodeShape:
    if not object_type:
        return "rect"
    return _SHAPE_BY_TYPE.get(object_type, "rect")


def _group_title(node: CoverageNode, group_by: Literal["object_type", "killchain"]) -> str:
    if group_by == "killchain":
        return node.killchain or ""
    return _SUBGRAPH_BY_TYPE.get(node.object_type, node.object_type.title())
