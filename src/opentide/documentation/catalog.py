"""Catalog utilities for documentation objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from opentide.core.registry import OpenTide
from opentide.documentation.types import DocumentRecord, DocumentScope
from opentide.generation import framework as fw


@dataclass(frozen=True)
class DiagramEntry:
    """Relationship entry used for documentation diagrams."""

    uuid: str
    relation: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class DocumentationCatalog:
    """In-memory catalog of typed objects to render."""

    rules: list[DocumentRecord]
    objectives: list[DocumentRecord]
    threats: list[DocumentRecord]

    def resolve_record(self, uuid: str) -> DocumentRecord | None:
        """Return typed catalog record for a UUID when present."""
        for records in (self.rules, self.objectives, self.threats):
            for record in records:
                if record.uuid == uuid:
                    return record
        return None

    def resolve_name(self, uuid: str) -> str:
        """Return display name for a UUID, falling back to the UUID itself."""
        record = self.resolve_record(uuid)
        if record is not None:
            return record.name
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
        """Flat list of related objects with relationship metadata."""
        rel = fw.relations_list(uuid, mode="flat", direction=direction)
        result: list[DiagramEntry] = []
        for relation, ids in rel.items():
            unique_ids = sorted(set(ids))
            for ref in unique_ids:
                result.append(
                    DiagramEntry(
                        uuid=ref,
                        relation=relation,
                        description=f"Related {relation}",
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
        return [entry.uuid for entry in self.related_entries(uuid, direction=direction)]

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
            if target:
                relation = str(entry.get("relation") or "").strip() or None
                description = str(entry.get("description") or "").strip() or None
                if relation and not description:
                    description = (
                        str(fw.get_vocab_entry("chaining_relations", relation, field="description"))
                        .strip()
                        or None
                    )
                chain.append(
                    DiagramEntry(
                        uuid=str(target),
                        relation=relation,
                        description=description,
                    )
                )
        return chain

    def chaining_uuids(self, threat_uuid: str) -> list[str]:
        """Compatibility helper returning only chaining UUIDs."""
        return [entry.uuid for entry in self.chaining_entries(threat_uuid)]


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
    return DocumentationCatalog(rules=rules, objectives=objectives, threats=threats)
