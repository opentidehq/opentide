"""Catalog utilities for documentation objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from opentide.core.registry import OpenTide
from opentide.documentation.types import DocumentRecord, DocumentScope
from opentide.generation import framework as fw


@dataclass(frozen=True)
class DocumentationCatalog:
    """In-memory catalog of typed objects to render."""

    rules: list[DocumentRecord]
    objectives: list[DocumentRecord]
    threats: list[DocumentRecord]

    def resolve_name(self, uuid: str) -> str:
        """Return display name for a UUID, falling back to the UUID itself."""
        obj = OpenTide.lookup(uuid)
        if obj is not None:
            return obj.name
        return uuid

    def related_uuids(
        self,
        uuid: str,
        *,
        direction: Literal["upstream", "downstream", "both"] = "downstream",
    ) -> list[str]:
        """Flat list of related object UUIDs."""
        rel = fw.relations_list(uuid, mode="flat", direction=direction)
        result: list[str] = []
        for ids in rel.values():
            result.extend(ids)
        return sorted(set(result))

    def chaining_uuids(self, threat_uuid: str) -> list[str]:
        """Linear chaining UUIDs from threat chaining config."""
        threat = OpenTide.Threats.get(threat_uuid)
        if threat is None or not threat.threat.chaining:
            return []
        chain: list[str] = []
        for entry in threat.threat.chaining:
            target = (
                entry.get("vector") or entry.get("target") or entry.get("uuid") or entry.get("id")
            )
            if target:
                chain.append(str(target))
        return chain


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
