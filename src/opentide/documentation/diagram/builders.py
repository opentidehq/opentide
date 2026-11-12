"""Build the diagrams object pages show, from the catalogue and the rule facts.

Three diagrams, each answering one question:

- **Detection coverage** (every page): how a threat is detected. Lanes run
  left to right: threat vectors, detection objectives, signals, rules, and,
  on a rule page, the platforms the rule deploys to with their status.
- **Threat chaining** (threat pages): what happens before, after and
  alongside a threat. Lanes are kill-chain phases in kill-chain order; every
  relation is drawn in its ``from`` direction, so arrows read one way, and the
  line style tells the relation family (sequence, composition, support).
- **Relations** (fallback): an object's direct neighbours, when it has no
  coverage path to draw.
"""

from __future__ import annotations

from collections.abc import Sequence, Set
from typing import Literal

from opentide.documentation.catalog import CoverageGraph, DocumentationCatalog
from opentide.documentation.diagram.mermaid import legend, render_mermaid
from opentide.documentation.diagram.model import Diagram, Lane, Link, LinkStyle, Node, NodeKind
from opentide.documentation.facts.deployment import PlatformDeployment
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.vocabulary import chaining_relation, vocabulary_order
from opentide.models.threat import ThreatVector

_KIND_BY_TYPE: dict[str, NodeKind] = {
    "threat": NodeKind.threat,
    "objective": NodeKind.objective,
    "signal": NodeKind.signal,
    "rule": NodeKind.rule,
}

_LANE_TITLES: dict[NodeKind, str] = {
    NodeKind.threat: "Threat vectors",
    NodeKind.objective: "Detection objectives",
    NodeKind.signal: "Signals",
    NodeKind.rule: "Detection rules",
    NodeKind.platform: "Platforms",
    NodeKind.tenant: "Tenants",
}

#: Line style of each chaining relation family (``tide.vocab.stages``).
_FAMILY_STYLES: dict[str, tuple[LinkStyle, str]] = {
    "sequence": (LinkStyle.solid, "sequence"),
    "atomicity": (LinkStyle.thick, "composition"),
    "support": (LinkStyle.dotted, "support"),
}


def render_diagram(formatter: MarkdownFormatter, diagram: Diagram | None) -> str:
    """*diagram* fenced for the flavor, followed by its legend; empty when trivial."""
    if diagram is None or diagram.is_trivial():
        return ""
    dialect = formatter.mermaid_dialect()
    fence = formatter.mermaid_fence(render_mermaid(diagram, dialect))
    return f"{fence.rstrip()}\n\n{legend(diagram, dialect)}\n"


def coverage_diagram(catalog: DocumentationCatalog, uuid: str, *, name: str) -> Diagram | None:
    """Threat-to-rule coverage around *uuid*."""
    graph = catalog.coverage_graph(uuid)
    if not isinstance(graph, CoverageGraph) or not graph.nodes:
        return None
    diagram = Diagram(
        title=f"Detection coverage of {name}",
        description=(
            "Threat vectors on the left are detected by the objectives, signals "
            "and rules to their right."
        ),
    )
    for node in graph.nodes:
        kind = _KIND_BY_TYPE.get(node.object_type)
        if kind is not None:
            diagram.add_node(Node(node.uuid, node.name, kind, focus=node.uuid == uuid))
    for edge in graph.edges:
        diagram.add_link(Link(edge.source, edge.target))
    diagram.lanes = _kind_lanes(diagram)
    return diagram


def deployment_diagram(
    uuid: str, *, name: str, deployments: Sequence[PlatformDeployment]
) -> Diagram | None:
    """Where a rule goes: each platform at its status, and the tenants each run reaches.

    A solid link is one a run takes, labelled with the runs (``PREVIEW``,
    ``RELEASE``); a dotted one is a status or a tenant no run deploys to.
    """
    if not deployments:
        return None
    diagram = Diagram(
        title=f"Deployment map of {name}",
        description=(
            "The platforms the rule deploys to, at their status, and the tenants each run reaches."
        ),
    )
    diagram.add_node(Node(uuid, name, NodeKind.rule, focus=True))
    for deployment in deployments:
        platform_key = f"{uuid}::{deployment.platform}"
        diagram.add_node(
            Node(platform_key, deployment.label, NodeKind.platform, caption=deployment.status)
        )
        diagram.add_link(
            Link(uuid, platform_key, style=LinkStyle.solid if deployment.runs else LinkStyle.dotted)
        )
        for target in deployment.targets:
            tenant_key = f"{platform_key}::{target.name}"
            caption = f"id {target.remote_id}" if target.remote_id else ""
            diagram.add_node(Node(tenant_key, target.name, NodeKind.tenant, caption=caption))
            runs = " + ".join(run.name for run in target.runs)
            style = LinkStyle.solid if target.runs else LinkStyle.dotted
            diagram.add_link(Link(platform_key, tenant_key, label=runs, style=style))
    diagram.link_legend[LinkStyle.solid] = "deployed, by the runs named on the line"
    diagram.link_legend[LinkStyle.dotted] = "not deployed: no run takes this status or tenant"
    diagram.lanes = [
        Lane(title, members)
        for title, members in (
            ("Detection rule", (uuid,)),
            (
                "Platforms",
                tuple(k for k, n in diagram.nodes.items() if n.kind is NodeKind.platform),
            ),
            ("Tenants", tuple(k for k, n in diagram.nodes.items() if n.kind is NodeKind.tenant)),
        )
        if members
    ]
    return diagram


def chaining_diagram(catalog: DocumentationCatalog, uuid: str, *, name: str) -> Diagram | None:
    """The chaining network of threat *uuid*, laned by kill-chain phase."""
    network = catalog.chaining_network(uuid)
    if not isinstance(network, CoverageGraph) or not network.edges:
        return _linear_chain(catalog, uuid, name=name)
    diagram = Diagram(
        title=f"Threat chaining of {name}",
        description="Threat vectors linked by chaining relations, grouped by kill-chain phase.",
    )
    for node in network.nodes:
        diagram.add_node(Node(node.uuid, node.name, NodeKind.threat, focus=node.uuid == uuid))
    for edge in network.edges:
        _add_chaining_link(diagram, edge.source, edge.target, edge.label or "")
    phases = {node.uuid: node.killchain or "" for node in network.nodes}
    diagram.lanes = _phase_lanes(phases)
    return diagram


#: Above this many threat vectors the landscape is too dense to read, and is left out.
LANDSCAPE_LIMIT = 60


def landscape_diagram(threats: Sequence[ThreatVector], *, addressed: Set[str]) -> Diagram | None:
    """Every threat vector of the catalogue by kill-chain phase, linked by chaining.

    Threats no detection objective addresses are drawn as gaps. Left out for a
    catalogue with fewer than two threats, or more than :data:`LANDSCAPE_LIMIT`.
    """
    if not 2 <= len(threats) <= LANDSCAPE_LIMIT:
        return None
    diagram = Diagram(
        title="Threat landscape",
        description=(
            "Every threat vector by kill-chain phase, linked by chaining relations; "
            "dashed ones have no detection objective."
        ),
    )
    phases: dict[str, str] = {}
    for threat in threats:
        uuid = threat.metadata.uuid
        gap = uuid not in addressed
        diagram.add_node(
            Node(uuid, threat.name, NodeKind.threat, caption="not covered" if gap else "", gap=gap)
        )
        killchain = threat.threat.killchain
        first = killchain if isinstance(killchain, str) else (killchain or [""])[0]
        phases[uuid] = first or ""
    for threat in threats:
        for entry in threat.threat.chaining or []:
            target = (
                entry.get("vector") or entry.get("target") or entry.get("uuid") or entry.get("id")
            )
            if target:
                relation = str(entry.get("relation") or "").strip()
                _add_chaining_link(diagram, threat.metadata.uuid, str(target), relation)
    diagram.lanes = _phase_lanes(phases)
    return diagram


def relations_diagram(
    catalog: DocumentationCatalog,
    uuid: str,
    *,
    name: str,
    kind: NodeKind,
    direction: Literal["upstream", "downstream", "both"] = "both",
) -> Diagram | None:
    """*uuid* and its direct neighbours, when there is no coverage path."""
    entries = catalog.related_entries(uuid, direction=direction)
    if not isinstance(entries, list) or not entries:
        return None
    diagram = Diagram(
        title=f"Relations of {name}",
        description="Objects this one references, and objects that reference it.",
    )
    diagram.add_node(Node(uuid, name, kind, focus=True))
    for entry in entries:
        entry_kind = _KIND_BY_TYPE.get(entry.object_type or "")
        if entry_kind is None:
            continue
        label = entry.name or catalog.resolve_name(entry.uuid)
        diagram.add_node(Node(entry.uuid, label, entry_kind))
        if entry.direction == "upstream":
            diagram.add_link(Link(entry.uuid, uuid))
        else:
            diagram.add_link(Link(uuid, entry.uuid))
    diagram.lanes = _kind_lanes(diagram)
    return diagram


def _linear_chain(catalog: DocumentationCatalog, uuid: str, *, name: str) -> Diagram | None:
    """The threat's own chaining entries, when the chaining index has none."""
    entries = catalog.chaining_entries(uuid)
    if not isinstance(entries, list) or not entries:
        return None
    diagram = Diagram(
        title=f"Threat chaining of {name}",
        description="Threat vectors this threat declares chaining relations to.",
    )
    diagram.add_node(Node(uuid, name, NodeKind.threat, focus=True))
    for entry in entries:
        label = entry.name or catalog.resolve_name(entry.uuid)
        diagram.add_node(Node(entry.uuid, label, NodeKind.threat))
        _add_chaining_link(diagram, uuid, entry.uuid, entry.relation or "")
    return diagram


def _add_chaining_link(diagram: Diagram, source: str, target: str, relation_key: str) -> None:
    relation = chaining_relation(relation_key) if relation_key else None
    if relation is None:
        diagram.add_link(Link(source, target))
        return
    style, family = _FAMILY_STYLES.get(relation.family, (LinkStyle.solid, relation.family))
    if family:
        diagram.link_legend.setdefault(style, family)
    if relation.reversed:
        source, target = target, source
    diagram.add_link(
        Link(
            source,
            target,
            label=relation.drawn_label,
            style=style,
            bidirectional=relation.bidirectional,
        )
    )


def _kind_lanes(diagram: Diagram) -> list[Lane]:
    lanes: list[Lane] = []
    for kind in NodeKind:
        members = tuple(node.key for node in diagram.nodes.values() if node.kind is kind)
        if members:
            lanes.append(Lane(_LANE_TITLES[kind], members))
    return lanes


def _phase_lanes(phases: dict[str, str]) -> list[Lane]:
    """One lane per kill-chain phase, in the order the vocabulary lists the phases."""
    order = {phase: index for index, phase in enumerate(vocabulary_order("killchain"))}
    named = sorted(
        {phase for phase in phases.values() if phase},
        key=lambda phase: (order.get(phase, len(order)), phase),
    )
    return [
        Lane(
            phase,
            tuple(uuid for uuid, value in phases.items() if value == phase),
            caption_fallback=True,
        )
        for phase in named
    ]
