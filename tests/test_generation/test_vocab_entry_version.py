"""Tests for VocabularyEntry version defaults."""

from __future__ import annotations

from opentide.generation.vocabulary import VocabularyEntry, _build_entry, parse_vocabulary_document


def test_vocabulary_entry_defaults_version() -> None:
    entry = VocabularyEntry(name="Alpha")
    assert entry.version == "1.0"
    assert entry.removed is None


def test_build_entry_backfills_missing_version() -> None:
    entry = _build_entry({"name": "Beta"}, fallback_name="Beta")
    assert entry.version == "1.0"


def test_parse_vocabulary_document_reads_per_key_version() -> None:
    raw = {
        "name": "Kill Chain",
        "field": "killchain",
        "keys": [
            {"name": "Legacy", "version": "1.0"},
            {"name": "Modern", "version": "1.1", "removed": "2.0"},
        ],
    }
    definition = parse_vocabulary_document(raw, source="killchain.vocab.toml")
    assert definition.entries["Legacy"].version == "1.0"
    assert definition.entries["Modern"].version == "1.1"
    assert definition.entries["Modern"].removed == "2.0"
