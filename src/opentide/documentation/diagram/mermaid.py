"""Render a :class:`~.model.Diagram` as Mermaid, within a flavor's capabilities.

Each wiki ships its own Mermaid release. GitHub and GitLab render subgraphs,
``classDef`` styles and the ``accTitle`` / ``accDescr`` accessibility lines;
Azure DevOps' wiki fails the whole diagram on some of them. A
:class:`MermaidDialect` says what a flavor can take, and :func:`render_mermaid`
writes the richest diagram that dialect renders. Everything a style conveys
(the kind of a node, the page's own object) is also carried by shape, label
and the legend, so a plain dialect loses colour, not meaning.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from opentide.documentation.diagram.model import Diagram, Lane, Link, LinkStyle, Node, NodeKind
from opentide.documentation.diagram.sanitize import edge_label, node_label


@dataclass(frozen=True)
class MermaidDialect:
    """The Mermaid features a Markdown flavor renders."""

    #: ``flowchart`` (Mermaid 8.6+) or the older ``graph`` keyword.
    keyword: Literal["flowchart", "graph"] = "flowchart"
    #: ``subgraph`` lanes.
    lanes: bool = True
    #: ``classDef`` / ``class`` colours and the focus outline.
    styles: bool = True
    #: ``accTitle`` / ``accDescr`` (Mermaid 9.4+), read by screen readers.
    accessibility: bool = True


@dataclass(frozen=True)
class KindStyle:
    """How one node kind is drawn and named in the legend."""

    prefix: str
    opening: str
    closing: str
    shape: str
    noun: str
    #: ``classDef`` body: a pale fill and dark text read on light and dark pages alike.
    css: str


KIND_STYLES: dict[NodeKind, KindStyle] = {
    NodeKind.threat: KindStyle(
        "thr", "{{", "}}", "hexagon", "threat vector", "fill:#fdecea,stroke:#b42318,color:#3d0c09"
    ),
    NodeKind.objective: KindStyle(
        "obj",
        "([",
        "])",
        "stadium",
        "detection objective",
        "fill:#fff4e5,stroke:#b54708,color:#3d1d02",
    ),
    NodeKind.signal: KindStyle(
        "sig", "((", "))", "circle", "detection signal", "fill:#eaf2fd,stroke:#1d4ed8,color:#0b1f4d"
    ),
    NodeKind.rule: KindStyle(
        "rul", "[", "]", "rectangle", "detection rule", "fill:#e9f7ef,stroke:#067647,color:#053321"
    ),
    NodeKind.platform: KindStyle(
        "plt",
        "[(",
        ")]",
        "cylinder",
        "platform deployment",
        "fill:#f2f4f7,stroke:#475467,color:#101828",
    ),
}

_FOCUS_CSS = "stroke-width:3px"
_LANE_CSS = "fill:transparent,stroke:#98a2b3,stroke-dasharray:4 4"

#: Arrow of each line style: (one-way, two-way).
_ARROWS: dict[LinkStyle, tuple[str, str]] = {
    LinkStyle.solid: ("-->", "<-->"),
    LinkStyle.thick: ("==>", "<==>"),
    LinkStyle.dotted: ("-.->", "<-.->"),
}

_LINE_NOUNS: dict[LinkStyle, str] = {
    LinkStyle.solid: "solid line",
    LinkStyle.thick: "thick line",
    LinkStyle.dotted: "dotted line",
}


def render_mermaid(diagram: Diagram, dialect: MermaidDialect) -> str:
    """The Mermaid source of *diagram* (no fence)."""
    ids = _assign_ids(diagram)
    lines = [f"{dialect.keyword} {diagram.direction}"]
    if dialect.accessibility:
        lines.append(f"    accTitle: {_single_line(diagram.title)}")
        if diagram.description:
            lines.append(f"    accDescr: {_single_line(diagram.description)}")

    placed: set[str] = set()
    lanes = [lane for lane in diagram.lanes if any(key in diagram.nodes for key in lane.members)]
    lane_ids: list[str] = []
    for index, lane in enumerate(lanes, start=1):
        members = _lane_members(diagram, lane, placed)
        if not members:
            continue
        if dialect.lanes:
            lane_id = f"lane{index}"
            lane_ids.append(lane_id)
            lines.append(f'    subgraph {lane_id}["{node_label(lane.title, width=0)}"]')
            lines.extend(f"        {_node(node, ids)}" for node in members)
            lines.append("    end")
        else:
            for node in members:
                if lane.caption_fallback and not node.caption:
                    node = replace(node, caption=lane.title)
                lines.append(f"    {_node(node, ids)}")
        placed.update(node.key for node in members)

    lines.extend(
        f"    {_node(node, ids)}" for node in diagram.nodes.values() if node.key not in placed
    )
    lines.extend(f"    {_link(link, ids)}" for link in diagram.links)

    if dialect.styles:
        lines.extend(_style_lines(diagram, ids, lane_ids))
    return "\n".join(lines)


def legend(diagram: Diagram, dialect: MermaidDialect) -> str:
    """One Markdown line naming each shape and line style the diagram uses."""
    shapes = [f"{KIND_STYLES[kind].shape} = {KIND_STYLES[kind].noun}" for kind in diagram.kinds()]
    if dialect.styles and any(node.focus for node in diagram.nodes.values()):
        shapes.append("bold outline = this page")
    parts = [f"*Shapes:* {'; '.join(shapes)}."]
    lines = [
        f"{_LINE_NOUNS[style]} = {diagram.link_legend[style]}"
        for style in diagram.link_styles()
        if diagram.link_legend.get(style)
    ]
    if lines:
        parts.append(f"*Lines:* {'; '.join(lines)}.")
    return " ".join(parts)


def _assign_ids(diagram: Diagram) -> dict[str, str]:
    """Short, stable Mermaid ids (``thr1``, ``rul3``) in insertion order.

    UUIDs make unreadable sources and can start with a digit; a reserved word
    (``end``) as an id breaks the parser. A kind prefix plus a counter is safe.
    """
    counters: dict[NodeKind, int] = {}
    ids: dict[str, str] = {}
    for node in diagram.nodes.values():
        counters[node.kind] = counters.get(node.kind, 0) + 1
        ids[node.key] = f"{KIND_STYLES[node.kind].prefix}{counters[node.kind]}"
    return ids


def _lane_members(diagram: Diagram, lane: Lane, placed: set[str]) -> list[Node]:
    members: list[Node] = []
    for key in lane.members:
        node = diagram.nodes.get(key)
        if node is not None and key not in placed and node not in members:
            members.append(node)
    return members


def _node(node: Node, ids: dict[str, str]) -> str:
    style = KIND_STYLES[node.kind]
    label = node_label(node.label)
    if node.caption:
        label = f"{label}<br>{node_label(node.caption)}"
    return f'{ids[node.key]}{style.opening}"{label}"{style.closing}'


def _link(link: Link, ids: dict[str, str]) -> str:
    one_way, two_way = _ARROWS[link.style]
    arrow = two_way if link.bidirectional else one_way
    text = edge_label(link.label) if link.label else ""
    middle = f'{arrow}|"{text}"|' if text else arrow
    return f"{ids[link.source]} {middle} {ids[link.target]}"


def _style_lines(diagram: Diagram, ids: dict[str, str], lane_ids: list[str]) -> list[str]:
    lines: list[str] = []
    kinds = diagram.kinds()
    for kind in kinds:
        lines.append(f"    classDef {kind.value} {KIND_STYLES[kind].css}")
    focus = [ids[node.key] for node in diagram.nodes.values() if node.focus]
    if focus:
        lines.append(f"    classDef focus {_FOCUS_CSS}")
    for kind in kinds:
        members = [ids[node.key] for node in diagram.nodes.values() if node.kind is kind]
        lines.append(f"    class {','.join(members)} {kind.value}")
    if focus:
        lines.append(f"    class {','.join(focus)} focus")
    lines.extend(f"    style {lane_id} {_LANE_CSS}" for lane_id in lane_ids)
    return lines


def _single_line(text: str) -> str:
    return " ".join(text.split())
