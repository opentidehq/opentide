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


@dataclass(frozen=True, slots=True)
class ChainingRelation:
    """How a chaining relation is drawn, read from ``chaining_relations``.

    The vocabulary pairs each relation with its inverse in one family
    (``preceeds`` / ``succeeds`` in ``sequence``): the ``from`` side points
    away from the threat that declares it, the ``to`` side towards it. A
    diagram draws every pair the ``from`` way, so all arrows in a chain read
    in one direction and ``A preceeds B`` and ``B succeeds A`` are one link.
    """

    key: str
    label: str
    #: ``sequence``, ``atomicity``, ``support``; empty when the vocabulary does not say.
    family: str = ""
    #: Draw the link from the target to the declaring threat, under ``inverse``.
    reversed: bool = False
    #: The ``from`` relation of the same family, used as the label of a reversed link.
    inverse: str = ""
    bidirectional: bool = False

    @property
    def drawn_label(self) -> str:
        """The label of the link as drawn."""
        return (self.inverse or self.label) if self.reversed else self.label


def chaining_relation(key: str) -> ChainingRelation:
    """The drawing semantics of chaining relation *key*; a plain forward link when unknown."""
    entries = _vocab_entries("chaining_relations")
    entry = entries.get(key)
    if entry is None:
        return ChainingRelation(key=key, label=key)
    kind = _as_text(entry.get("tide.vocab.relation.type"))
    family = _first_text(entry.get("tide.vocab.stages"))
    inverse = ""
    if kind == "to":
        inverse = next(
            (
                _as_text(other.get("name")) or other_key
                for other_key, other in entries.items()
                if _as_text(other.get("tide.vocab.relation.type")) == "from"
                and _first_text(other.get("tide.vocab.stages")) == family
            ),
            "",
        )
    return ChainingRelation(
        key=key,
        label=_as_text(entry.get("name")) or key,
        family=family,
        reversed=kind == "to",
        inverse=inverse,
        bidirectional=kind == "bidirectional",
    )


def vocabulary_order(vocab: str) -> list[str]:
    """The entry keys of *vocab* in the order the vocabulary declares them."""
    return list(_vocab_entries(vocab))


def _vocab_entries(vocab: str) -> dict[str, Any]:
    from opentide.generation.framework import VOCAB_INDEX

    if vocab not in VOCAB_INDEX:
        return {}
    return dict(VOCAB_INDEX[vocab].entries)


def _first_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and value and isinstance(value[0], str):
        return value[0]
    return ""
