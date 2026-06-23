"""VocabularyResolver behavioural coverage."""

from __future__ import annotations

import pytest


def test_vocabulary_resolve_emits_entry_names(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.generation import schema_pipeline
    from opentide.generation.vocabulary import (
        VocabularyDefinition,
        VocabularyEntry,
        VocabularyMetadata,
    )
    vocab = VocabularyDefinition(
        metadata=VocabularyMetadata(name="Severity", field="severity"),
        entries={
            "High": VocabularyEntry(name="High", description="High severity"),
            "Low": VocabularyEntry(name="Low", description="Low severity"),
        },
    )
    monkeypatch.setattr(schema_pipeline, "VOCAB_INDEX", {"severity": vocab})
    monkeypatch.setattr(schema_pipeline, "VOCAB_EXTENSIONS", {})

    resolver = schema_pipeline.VocabularyResolver.Vocabulary("severity")
    enum, descriptions = resolver.resolve()

    assert "High" in enum
    assert "Low" in enum
    assert len(descriptions) == len(enum)


def test_vocabulary_resolve_empty_vocab_returns_placeholder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentide.generation import schema_pipeline
    monkeypatch.setattr(schema_pipeline, "VOCAB_INDEX", {})
    monkeypatch.setattr(schema_pipeline, "VOCAB_EXTENSIONS", {})

    resolver = schema_pipeline.VocabularyResolver.Vocabulary("missing")
    enum, descriptions = resolver.resolve()

    assert enum == [""]
    assert descriptions == []


def test_vocabulary_finalise_appends_hints_separately(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hints must extend descriptions via _hint_descriptions, not self.enum_description."""
    from opentide.generation import schema_pipeline
    from opentide.generation.vocabulary import (
        VocabularyDefinition,
        VocabularyEntry,
        VocabularyMetadata,
    )
    vocab = VocabularyDefinition(
        metadata=VocabularyMetadata(
            name="Impact",
            field="impact",
            extra={"vocab.search_hints": True},
        ),
        entries={"A": VocabularyEntry(name="Alpha", description="First", extra={"alias": ["a"]})},
    )
    monkeypatch.setattr(schema_pipeline, "VOCAB_INDEX", {"impact": vocab})
    monkeypatch.setattr(schema_pipeline, "VOCAB_EXTENSIONS", {})

    resolver = schema_pipeline.VocabularyResolver.Vocabulary("impact")
    enum, descriptions = resolver.resolve()

    assert len(enum) >= 1
    assert len(descriptions) == len(enum)
