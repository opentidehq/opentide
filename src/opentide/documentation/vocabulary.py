"""Documentation vocabulary enrichment helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from opentide.generation.framework import get_vocab_entry


@dataclass(frozen=True, slots=True)
class EnrichedEntry:
    """Normalized vocabulary entry for documentation rendering."""

    key: str
    label: str
    description: str = ""
    icon: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def enrich(vocab: str, key: str) -> EnrichedEntry:
    """Return enriched entry metadata, falling back to the raw key."""
    raw_entry = get_vocab_entry(vocab, key)
    if not isinstance(raw_entry, dict):
        return EnrichedEntry(key=key, label=key)

    label = _as_text(raw_entry.get("name")) or _as_text(raw_entry.get("label")) or key
    return EnrichedEntry(
        key=key,
        label=label,
        description=_as_text(raw_entry.get("description")),
        icon=_as_text(raw_entry.get("icon")),
        raw=raw_entry,
    )


def enrich_technique(technique: str) -> EnrichedEntry:
    """Convenience helper for ATT&CK techniques."""
    return enrich("att&ck", technique)


def chaining_relation_label(relation: str) -> str:
    """Resolve a readable label for a chaining relation."""
    return enrich("chaining_relations", relation).label


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return ""
