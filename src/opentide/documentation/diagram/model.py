"""A flavor-neutral diagram model, rendered to Mermaid by :mod:`.mermaid`.

Builders describe *what* a diagram shows (typed nodes, typed links, ordered
lanes); the renderer decides *how*, from the Markdown flavor's
:class:`~opentide.documentation.diagram.mermaid.MermaidDialect`. Nothing here
knows Mermaid syntax, so a builder never has to care which features a wiki's
Mermaid version supports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

Direction = Literal["LR", "TB"]


class NodeKind(str, Enum):
    """What a node stands for. Each kind has one shape and one style."""

    threat = "threat"
    objective = "objective"
    signal = "signal"
    rule = "rule"
    platform = "platform"


class LinkStyle(str, Enum):
    """How a link is drawn: the line carries meaning, not only the label."""

    #: A plain dependency or sequence.
    solid = "solid"
    #: A strong, structural link (one object is composed of the other).
    thick = "thick"
    #: A weak or inactive link (support, or a disabled deployment).
    dotted = "dotted"


@dataclass(frozen=True)
class Node:
    """One box. ``key`` is the stable identity (a UUID); the renderer assigns the Mermaid id."""

    key: str
    label: str
    kind: NodeKind
    #: A second, smaller line under the label (a status, a kill-chain phase).
    caption: str = ""
    #: The object the page is about.
    focus: bool = False


@dataclass(frozen=True)
class Link:
    """A directed link between two node keys."""

    source: str
    target: str
    label: str = ""
    style: LinkStyle = LinkStyle.solid
    bidirectional: bool = False


@dataclass(frozen=True)
class Lane:
    """A titled group of nodes, drawn as a subgraph where the flavor supports one."""

    title: str
    members: tuple[str, ...]
    #: Where lanes cannot be drawn, show the title under each member's label,
    #: for lanes that say something the shape does not (a kill-chain phase).
    caption_fallback: bool = False


@dataclass
class Diagram:
    """An ordered, de-duplicated graph. Insertion order is render order."""

    title: str
    description: str = ""
    direction: Direction = "LR"
    nodes: dict[str, Node] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    lanes: list[Lane] = field(default_factory=list)
    #: Text for each link style the legend explains, when the style is drawn.
    link_legend: dict[LinkStyle, str] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        """Add *node* unless its key is present; a focus node wins over a plain one."""
        existing = self.nodes.get(node.key)
        if existing is None or (node.focus and not existing.focus):
            self.nodes[node.key] = node

    def add_link(self, link: Link) -> None:
        """Add *link* between known nodes, once."""
        if link.source not in self.nodes or link.target not in self.nodes:
            return
        if link.source == link.target:
            return
        for existing in self.links:
            same = (existing.source, existing.target) == (link.source, link.target)
            mirrored = (existing.source, existing.target) == (link.target, link.source)
            if (same or (mirrored and existing.bidirectional)) and existing.label == link.label:
                return
        self.links.append(link)

    def is_trivial(self) -> bool:
        """True when there is nothing worth drawing: a lone node, or nothing."""
        return not self.links

    def kinds(self) -> list[NodeKind]:
        """The node kinds present, in :class:`NodeKind` order."""
        present = {node.kind for node in self.nodes.values()}
        return [kind for kind in NodeKind if kind in present]

    def link_styles(self) -> list[LinkStyle]:
        """The link styles drawn, in :class:`LinkStyle` order."""
        present = {link.style for link in self.links}
        return [style for style in LinkStyle if style in present]
