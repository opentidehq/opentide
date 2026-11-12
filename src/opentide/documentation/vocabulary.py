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


def killchain_stages() -> list[tuple[str, list[str]]]:
    """The kill chain's stages in order, each with its phases in order.

    The Unified Kill Chain groups its 18 phases into Initial Foothold, Network
    Propagation and Action on Objectives (each entry's ``tide.vocab.stages``).
    A phase without a stage gets a group of its own name, so none is lost.
    """
    from opentide.generation.framework import VOCAB_INDEX

    if "killchain" not in VOCAB_INDEX:
        return []
    vocabulary = VOCAB_INDEX["killchain"]
    declared = [
        str(stage.get("name"))
        for stage in (vocabulary.metadata.stages or [])
        if isinstance(stage, dict) and stage.get("name")
    ]
    groups: dict[str, list[str]] = {name: [] for name in declared}
    for key, entry in vocabulary.entries.items():
        stage = _first_text(entry.get("tide.vocab.stages")) or key
        groups.setdefault(stage, []).append(key)
    return [(stage, phases) for stage, phases in groups.items() if phases]


def killchain_stage(phase: str) -> str:
    """The stage *phase* belongs to, or an empty string."""
    for stage, phases in killchain_stages():
        if phase in phases:
            return stage
    return ""


def attack_tactics() -> list[str]:
    """ATT&CK's tactics in matrix order, as the vocabulary's release names them."""
    from opentide.generation.framework import VOCAB_INDEX

    if "att&ck" not in VOCAB_INDEX:
        return []
    stages = VOCAB_INDEX["att&ck"].metadata.stages or []
    return [
        str(stage.get("name")) for stage in stages if isinstance(stage, dict) and stage.get("name")
    ]


def technique_tactics(technique: str) -> list[str]:
    """The tactics a technique serves, in matrix order."""
    entry = enrich_technique(technique)
    raw = entry.raw.get("tide.vocab.stages") if entry.raw else None
    tactics = [raw] if isinstance(raw, str) else [str(item) for item in raw or () if item]
    order = {tactic: index for index, tactic in enumerate(attack_tactics())}
    return sorted(dict.fromkeys(tactics), key=lambda tactic: order.get(tactic, len(order)))


def covers_technique(detected: str, wanted: str) -> bool:
    """Whether detecting *detected* detects *wanted*: the same technique, or one of its subs."""
    return detected == wanted or detected.startswith(f"{wanted}.")


def actor_aliases(actor: str) -> list[str]:
    """Other names of an ATT&CK group (``att&ck::G0016`` is also Cozy Bear, Midnight Blizzard)."""
    from opentide.generation.framework import VOCAB_INDEX

    group_id = actor.split("::")[-1]
    groups = VOCAB_INDEX.get("att&ck.groups")
    entry = groups.entries.get(group_id) if groups is not None else None
    raw = entry.get("alias") if entry is not None else None
    if not isinstance(raw, (list, tuple)):
        return []
    name = _as_text(entry.get("name")) if entry is not None else ""
    return [str(alias) for alias in raw if alias and str(alias) != name]
