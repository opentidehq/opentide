"""Vocabulary enrichment helpers for documentation rendering."""

from __future__ import annotations

from opentide.documentation.vocabulary import (
    EnrichedEntry,
    chaining_relation_label,
    enrich,
    enrich_technique,
)


def test_enrich_returns_structured_vocab_entry(monkeypatch) -> None:
    monkeypatch.setattr(
        "opentide.documentation.vocabulary.get_vocab_entry",
        lambda vocab, key: {
            "name": "Suspicious Process Tree",
            "description": "Maps to a composite ATT&CK behavior.",
            "icon": "activity",
            "extra": "kept in raw",
        },
    )

    entry = enrich("att&ck", "T1059")

    assert entry == EnrichedEntry(
        key="T1059",
        label="Suspicious Process Tree",
        description="Maps to a composite ATT&CK behavior.",
        icon="activity",
        raw={
            "name": "Suspicious Process Tree",
            "description": "Maps to a composite ATT&CK behavior.",
            "icon": "activity",
            "extra": "kept in raw",
        },
    )


def test_enrich_falls_back_when_vocab_or_entry_missing(monkeypatch) -> None:
    monkeypatch.setattr(
        "opentide.documentation.vocabulary.get_vocab_entry",
        lambda _vocab, _key: "",
    )

    entry = enrich("missing_vocab", "unknown-key")

    assert entry == EnrichedEntry(key="unknown-key", label="unknown-key")


def test_enrich_technique_uses_attack_vocabulary(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def _fake_get_vocab_entry(vocab: str, key: str):
        calls.append((vocab, key))
        return {"name": "Technique Name"}

    monkeypatch.setattr("opentide.documentation.vocabulary.get_vocab_entry", _fake_get_vocab_entry)

    entry = enrich_technique("T1021")

    assert calls == [("att&ck", "T1021")]
    assert entry.label == "Technique Name"


def test_chaining_relation_label_falls_back_to_relation(monkeypatch) -> None:
    monkeypatch.setattr(
        "opentide.documentation.vocabulary.get_vocab_entry",
        lambda _vocab, _key: "",
    )

    assert chaining_relation_label("support::enabled") == "support::enabled"
