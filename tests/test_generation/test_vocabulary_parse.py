"""Tests for generation vocabulary parsing."""

from __future__ import annotations

import pytest

from opentide.generation.vocabulary import VocabularyLoadError, parse_vocabulary_document


def test_parse_vocabulary_document_requires_name() -> None:
    with pytest.raises(VocabularyLoadError, match="Missing required key 'name'"):
        parse_vocabulary_document({"field": "severity"}, source="test.toml")


def test_parse_vocabulary_document_minimal() -> None:
    raw = {
        "name": "Severity",
        "field": "severity",
        "key": "name",
        "entries": [{"name": "High"}],
    }
    definition = parse_vocabulary_document(raw, source="severity.vocab.toml")
    assert definition.metadata.field == "severity"
    assert definition.metadata.name == "Severity"
