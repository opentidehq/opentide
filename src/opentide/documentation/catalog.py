"""Catalog utilities for documentation objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from opentide.core.registry import OpenTide
from opentide.documentation.types import DocumentRecord, DocumentScope
from opentide.generation import framework as fw
from opentide.models.objective import DetectionObjective
from opentide.models.threat import ThreatVector

RelationDirection = Literal["upstream", "downstream"]
ChainingArrow = Literal["forward", "bidirectional"]


@dataclass(frozen=True)
class SignalRecord:
    """Nested signal that lives on an objective wiki page."""

    uuid: str
    name: str
    parent_uuid: str
    parent_name: str


@dataclass(frozen=True)
class DiagramEntry:
    """Relationship entry used for documentation diagrams and tables."""

    uuid: str
    relation: str | None = None
    description: str | None = None
    object_type: str | None = None
    direction: RelationDirection | None = None
    name: str | None = None


@dataclass(frozen=True)
class CoverageNode:
    """Typed node in a coverage or chaining diagram."""

    uuid: str
    name: str
    object_type: str
    killchain: str | None = None


@dataclass(frozen=True)
class CoverageEdge:
    """Directed edge in a coverage or chaining diagram."""

    source: str
    target: str
    label: str | None = None
    arrow: ChainingArrow = "forward"


@dataclass(frozen=True)
class CoverageGraph:
    """Small typed graph for Mermaid rendering."""

    nodes: list[CoverageNode] = field(default_factory=list)
    edges: list[CoverageEdge] = field(default_factory=list)

    def is_empty(self) -> bool:
        """True when the graph has nothing useful to draw."""
        return not self.edges and len(self.nodes) <= 1


@dataclass(frozen=True)
class DocumentationCatalog:
    """In-memory catalog of typed objects to render."""

    rules: list[DocumentRecord]
    objectives: list[DocumentRecord]
    threats: list[DocumentRecord]
    signals: list[SignalRecord] = field(default_factory=list)

    def resolve_record(self, uuid: str) -> DocumentRecord | None:
        """Return typed catalog record for a UUID when present."""
        for records in (self.rules, self.objectives, self.threats):
            for record in records:
                if record.uuid == uuid:
                    return record
        return None

    def resolve_signal(self, uuid: str) -> SignalRecord | None:
        """Return nested signal metadata when the UUID is a signal."""
        for signal in self.signals:
            if signal.uuid == uuid:
                return signal
        return None

    def resolve_name(self, uuid: str) -> str:
        """Return display name for a UUID, falling back to the UUID itself."""
        record = self.resolve_record(uuid)
        if record is not None:
            return record.name
        signal = self.resolve_signal(uuid)
        if signal is not None:
            return signal.name
        obj = OpenTide.lookup(uuid)
        if obj is not None:
            return obj.name
        return uuid

    def related_entries(
        self,
        uuid: str,
        *,
        direction: Literal["upstream", "downstream", "both"] = "downstream",
    ) -> list[DiagramEntry]:
        """Flat list of related objects with relationship metadata.

        Walks upstream and downstream separately so same-type keys from
        ``relations_list(..., direction="both")`` cannot clobber each other.
        """
        directions: tuple[RelationDirection, ...] = (
            ("upstream", "downstream") if direction == "both" else (direction,)
        )

        result: list[DiagramEntry] = []
        seen: set[tuple[str, str, str]] = set()
        for walk in directions:
            rel = _safe_relations(uuid, walk)
            for object_type, ids in rel.items():
                unique_ids = sorted(set(ids))
                for ref in unique_ids:
                    if ref == uuid:
                        continue
                    key = (ref, walk, str(object_type))
                    if key in seen:
                        continue
                    seen.add(key)
                    result.append(
                        DiagramEntry(
                            uuid=ref,
                            relation=str(object_type),
                            description=f"Related {object_type}",
                            object_type=str(object_type),
                            direction=walk,
                            name=self.resolve_name(ref),
                        )
                    )
        return result

    def related_uuids(
        self,
        uuid: str,
        *,
        direction: Literal["upstream", "downstream", "both"] = "downstream",
    ) -> list[str]:
        """Compatibility helper returning only related UUIDs."""
        seen: list[str] = []
        for entry in self.related_entries(uuid, direction=direction):
            if entry.uuid not in seen:
                seen.append(entry.uuid)
        return seen

    def chaining_entries(self, threat_uuid: str) -> list[DiagramEntry]:
        """Linear chaining entries from threat chaining config."""
        threat = OpenTide.Threats.get(threat_uuid)
        if threat is None or not threat.threat.chaining:
            return []
        chain: list[DiagramEntry] = []
        for entry in threat.threat.chaining:
            target = (
                entry.get("vector") or entry.get("target") or entry.get("uuid") or entry.get("id")
            )
            if not target:
                continue
            relation = str(entry.get("relation") or "").strip() or None
            description = str(entry.get("description") or "").strip() or None
            if relation and not description:
                description = (
                    str(
                        fw.get_vocab_entry("chaining_relations", relation, field="description")
                    ).strip()
                    or None
                )
            chain.append(
                DiagramEntry(
                    uuid=str(target),
                    relation=relation,
                    description=description,
                    object_type="threat",
                    direction="downstream",
                    name=self.resolve_name(str(target)),
                )
            )
        return chain

    def chaining_uuids(self, threat_uuid: str) -> list[str]:
        """Compatibility helper returning only chaining UUIDs."""
        return [entry.uuid for entry in self.chaining_entries(threat_uuid)]

    def chaining_network(self, threat_uuid: str) -> CoverageGraph:
        """Inbound + outbound threat chaining graph for Mermaid."""
        chain: dict[str, dict[str, list[str]]] = {}
        try:
            index = dict(OpenTide.Models.chaining or {})
        except Exception:
            index = {}
        for vector, links in index.items():
            if not isinstance(links, dict):
                continue
            for relation, targets in links.items():
                if threat_uuid not in (targets or []):
                    continue
                chain.setdefault(str(vector), {}).setdefault(str(relation), [])
                if threat_uuid not in chain[str(vector)][str(relation)]:
                    chain[str(vector)][str(relation)].append(threat_uuid)
        try:
            for vector in list(chain):
                chain = fw.chain_resolver(vector, chain)
            chain = fw.chain_resolver(threat_uuid, chain)
        except Exception:
            pass
        for entry in self.chaining_entries(threat_uuid):
            relation = entry.relation or "related"
            chain.setdefault(threat_uuid, {}).setdefault(relation, [])
            if entry.uuid not in chain[threat_uuid][relation]:
                chain[threat_uuid][relation].append(entry.uuid)

        nodes: dict[str, CoverageNode] = {}
        edges: list[CoverageEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()

        def add_threat(uid: str) -> None:
            uid = str(uid)
            if not uid or uid in nodes:
                return
            record = self.resolve_record(uid)
            name = record.name if record is not None else self.resolve_name(uid)
            nodes[uid] = CoverageNode(
                uid,
                name,
                "threat",
                killchain=_killchain_label(record.model if record is not None else None),
            )

        add_threat(threat_uuid)
        for source, links in chain.items():
            add_threat(str(source))
            for relation, targets in links.items():
                rel_key = str(relation).split("::")[-1]
                arrow = _chaining_arrow(rel_key)
                for target in targets:
                    add_threat(str(target))
                    if str(source) not in nodes or str(target) not in nodes:
                        continue
                    key = (str(source), str(target), rel_key)
                    if key in seen_edges:
                        continue
                    seen_edges.add(key)
                    edges.append(
                        CoverageEdge(
                            str(source),
                            str(target),
                            rel_key,
                            arrow=arrow,
                        )
                    )
        return CoverageGraph(nodes=list(nodes.values()), edges=edges)

    def coverage_graph(self, uuid: str) -> CoverageGraph:
        """2-hop threat → objective → signal → rule graph centred on ``uuid``."""
        record = self.resolve_record(uuid)
        if record is None:
            return CoverageGraph()

        nodes: dict[str, CoverageNode] = {}
        edges: list[CoverageEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()

        def add_node(uid: str, object_type: str, name: str) -> None:
            nodes.setdefault(uid, CoverageNode(uid, name, object_type))

        def add_edge(source: str, target: str, label: str | None) -> None:
            if source not in nodes or target not in nodes:
                return
            key = (source, target, label or "")
            if key in seen_edges:
                return
            seen_edges.add(key)
            edges.append(CoverageEdge(source, target, label))

        def add_objective(obj_uuid: str) -> None:
            obj_record = self.resolve_record(obj_uuid)
            if obj_record is None or obj_record.object_type != DocumentScope.objectives:
                return
            objective = obj_record.model
            if not isinstance(objective, DetectionObjective):
                return
            add_node(obj_uuid, "objective", obj_record.name)
            for threat_uuid in objective.objective.threats or []:
                threat_record = self.resolve_record(threat_uuid)
                if threat_record is None:
                    continue
                add_node(threat_uuid, "threat", threat_record.name)
                add_edge(threat_uuid, obj_uuid, "covers")
            linked_rules: set[str] = set()
            for signal in objective.objective.signals:
                add_node(signal.uuid, "signal", signal.name)
                add_edge(obj_uuid, signal.uuid, None)
                for rule_uuid in self.rules_for_signal(signal.uuid):
                    rule_record = self.resolve_record(rule_uuid)
                    if rule_record is None:
                        continue
                    add_node(rule_uuid, "rule", rule_record.name)
                    add_edge(signal.uuid, rule_uuid, "implements")
                    linked_rules.add(rule_uuid)
            for rule_record in self.rules:
                if getattr(rule_record.model, "detection_model", None) != obj_uuid:
                    continue
                add_node(rule_record.uuid, "rule", rule_record.name)
                if rule_record.uuid not in linked_rules:
                    add_edge(obj_uuid, rule_record.uuid, "implements")

        if record.object_type == DocumentScope.threats:
            add_node(uuid, "threat", record.name)
            for obj_record in self.objectives:
                body = getattr(obj_record.model, "objective", None)
                threats = getattr(body, "threats", None) or []
                if uuid in threats:
                    add_objective(obj_record.uuid)
        elif record.object_type == DocumentScope.objectives:
            add_objective(uuid)
        elif record.object_type == DocumentScope.rules:
            add_node(uuid, "rule", record.name)
            detection_model = getattr(record.model, "detection_model", None)
            if isinstance(detection_model, str) and detection_model:
                add_objective(detection_model)

        return CoverageGraph(nodes=list(nodes.values()), edges=edges)

    def rules_for_signal(self, signal_uuid: str) -> list[str]:
        """Return MDR UUIDs that implement a detection signal."""
        downstream: set[str] = set()
        try:
            if fw.get_type(signal_uuid, mute=True) != "signal":
                return []
            for child_uuid in fw.childs(signal_uuid):
                if fw.get_type(child_uuid, mute=True) == "rule":
                    downstream.add(child_uuid)
        except Exception:
            pass
        try:
            relations = fw.relations_list(signal_uuid, mode="flat", direction="downstream")
            for rule_uuid in relations.get("rule", []):
                downstream.add(rule_uuid)
        except Exception:
            pass
        known = {record.uuid for record in self.rules}
        return sorted(uid for uid in downstream if uid in known) or sorted(downstream)


def build_catalog() -> DocumentationCatalog:
    """Build a deterministic catalog for rule/objective/threat objects."""
    rules = [
        DocumentRecord(DocumentScope.rules, obj.metadata.uuid, obj.name, obj)
        for obj in sorted(OpenTide.Rules.values(), key=lambda item: item.name.lower())
    ]
    objectives = [
        DocumentRecord(DocumentScope.objectives, obj.metadata.uuid, obj.name, obj)
        for obj in sorted(OpenTide.Objectives.values(), key=lambda item: item.name.lower())
    ]
    threats = [
        DocumentRecord(DocumentScope.threats, obj.metadata.uuid, obj.name, obj)
        for obj in sorted(OpenTide.Threats.values(), key=lambda item: item.name.lower())
    ]
    signals: list[SignalRecord] = []
    for record in objectives:
        objective = record.model
        if not isinstance(objective, DetectionObjective):
            continue
        for signal in objective.objective.signals:
            signals.append(
                SignalRecord(
                    uuid=signal.uuid,
                    name=signal.name,
                    parent_uuid=record.uuid,
                    parent_name=record.name,
                )
            )
    return DocumentationCatalog(
        rules=rules,
        objectives=objectives,
        threats=threats,
        signals=signals,
    )


def _safe_relations(uuid: str, direction: RelationDirection) -> dict[str, list[str]]:
    try:
        rel = fw.relations_list(uuid, mode="flat", direction=direction)
    except Exception:
        return {}
    if not isinstance(rel, dict):
        return {}
    result: dict[str, list[str]] = {}
    for key, value in rel.items():
        if isinstance(value, list):
            result[str(key)] = [str(item) for item in value]
        elif isinstance(value, str):
            result[str(key)] = [value]
    return result


def _chaining_arrow(relation: str) -> ChainingArrow:
    raw = fw.get_vocab_entry("chaining_relations", relation, field="tide.vocab.relation.type")
    if str(raw).strip() == "bidirectional":
        return "bidirectional"
    return "forward"


def _killchain_label(model: object) -> str | None:
    if not isinstance(model, ThreatVector):
        return None
    killchain = model.threat.killchain
    if isinstance(killchain, list) and killchain:
        return str(killchain[0])
    if isinstance(killchain, str) and killchain:
        return killchain
    return None
