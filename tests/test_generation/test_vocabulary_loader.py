"""VocabularyLoader index-shaped loading."""

from __future__ import annotations

import pytest

from opentide.generation.vocabulary import (
    VocabularyLoader,
    VocabularyLoadError,
)


def test_vocabulary_loader_from_index_dict() -> None:
    raw = {
        "metadata": {
            "name": "Severity",
            "field": "severity",
            "key": "name",
        },
        "entries": {
            "High": {"name": "High", "description": "High severity"},
        },
    }
    definition = VocabularyLoader.load(raw, source="severity")
    assert definition.metadata.field == "severity"
    assert "High" in definition.entries


def test_vocabulary_loader_missing_metadata_raises() -> None:
    with pytest.raises(VocabularyLoadError, match="Missing 'metadata'"):
        VocabularyLoader.load({"entries": {}}, source="bad")


def test_vocabulary_loader_missing_entries_raises() -> None:
    with pytest.raises(VocabularyLoadError, match="Missing 'entries'"):
        VocabularyLoader.load({"metadata": {"name": "X", "field": "x"}}, source="bad")


def test_vocabulary_loader_skips_malformed_entry() -> None:
    raw = {
        "metadata": {"name": "Tags", "field": "tags", "key": "name"},
        "entries": {"bad": "not-a-mapping", "Good": {"name": "Good"}},
    }
    definition = VocabularyLoader.load(raw, source="tags")
    assert len(definition.entries) == 1
