"""Unit tests for the typed vocabulary system (Phase 3)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Engines.modules.vocabulary import (  # noqa: E402
    entry_key_field,
    normalize_stages,
    parse_yaml_vocabulary,
    VocabularyDefinition,
    VocabularyEntry,
    VocabularyLoadError,
    VocabularyLoader,
    VocabularyMetadata,
)


def test_normalize_stages_none() -> None:
    assert normalize_stages(None) == []


def test_normalize_stages_string() -> None:
    assert normalize_stages("OS") == ["OS"]


def test_normalize_stages_list() -> None:
    assert normalize_stages(["OS", "Cloud"]) == ["OS", "Cloud"]


def test_entry_key_field_model() -> None:
    assert entry_key_field(model=True) == "id"
    assert entry_key_field(model=False) == "name"


def test_vocabulary_loader_load_valid() -> None:
    raw = {
        "metadata": {
            "name": "Impact",
            "field": "impact",
            "description": "Impact levels",
            "icon": "💥",
        },
        "entries": {
            "Nuisance": {
                "name": "Nuisance",
                "description": "Small impact",
                "tide.vocab.stages": "OS",
            }
        },
    }
    vocabulary = VocabularyLoader.load(raw, source="impact")
    assert vocabulary.metadata.name == "Impact"
    assert vocabulary.entries["Nuisance"].description == "Small impact"
    assert vocabulary.entries["Nuisance"].stages == ("OS",)


def test_vocabulary_loader_missing_metadata() -> None:
    with pytest.raises(VocabularyLoadError, match="Missing 'metadata'"):
        VocabularyLoader.load({"entries": {}}, source="broken")


def test_vocabulary_loader_missing_entries() -> None:
    with pytest.raises(VocabularyLoadError, match="Missing 'entries'"):
        VocabularyLoader.load({"metadata": {"name": "x"}}, source="broken")


def test_vocabulary_loader_skips_malformed_entry() -> None:
    raw = {
        "metadata": {"name": "Test", "field": "test"},
        "entries": {
            "good": {"name": "Good"},
            "bad": "not-a-mapping",
        },
    }
    vocabulary = VocabularyLoader.load(raw, source="test")
    assert "good" in vocabulary.entries
    assert "bad" not in vocabulary.entries


def test_parse_yaml_vocabulary() -> None:
    raw = {
        "name": "Severity",
        "field": "severity",
        "description": "Severity scale",
        "keys": [
            {"name": "Low", "description": "Low severity"},
            {"name": "High", "description": "High severity", "tide.vocab.stages": ["A", "B"]},
        ],
    }
    vocabulary = parse_yaml_vocabulary(raw, source="Severity.yaml")
    assert vocabulary.metadata.field == "severity"
    assert vocabulary.entries["Low"].description == "Low severity"
    assert vocabulary.entries["High"].stages == ("A", "B")


def test_parse_yaml_vocabulary_model_keys_use_id() -> None:
    raw = {
        "name": "Rules",
        "field": "mdr",
        "model": True,
        "keys": [{"id": "uuid-1", "name": "Rule One"}],
    }
    vocabulary = parse_yaml_vocabulary(raw, source="rules.yaml")
    assert "uuid-1" in vocabulary.entries
    assert vocabulary.entries["uuid-1"].name == "Rule One"


def test_parse_yaml_vocabulary_empty_keys_allowed() -> None:
    raw = {
        "name": "Responders",
        "field": "responders",
        "description": "Instance-defined",
        "keys": [],
    }
    vocabulary = parse_yaml_vocabulary(raw, source="responders.yaml")
    assert vocabulary.metadata.field == "responders"
    assert vocabulary.entries == {}


def test_parse_yaml_vocabulary_missing_required() -> None:
    with pytest.raises(VocabularyLoadError, match="Missing required key 'keys'"):
        parse_yaml_vocabulary({"name": "X", "field": "x"}, source="bad.yaml")


def test_vocabulary_entry_as_dict_roundtrip() -> None:
    entry = VocabularyEntry(
        name="Windows",
        description="Microsoft Windows",
        icon="💻",
        link="https://example.com",
        stages=("OS",),
        extra={"alias": ["win"]},
    )
    payload = entry.as_dict()
    assert payload["name"] == "Windows"
    assert payload["tide.vocab.stages"] == ["OS"]
    assert payload["alias"] == ["win"]


def test_vocabulary_metadata_get_extra_fields() -> None:
    metadata = VocabularyMetadata(
        name="Surface",
        field="surface",
        extra={"vocab.search_hints": False, "reference": "https://example.com"},
    )
    assert metadata.get("vocab.search_hints") is False
    assert metadata.get("reference") == "https://example.com"


def test_vocabulary_definition_to_index_dict() -> None:
    vocabulary = VocabularyDefinition(
        metadata=VocabularyMetadata(name="Test", field="test"),
        entries={"A": VocabularyEntry(name="A")},
    )
    payload = vocabulary.to_index_dict()
    assert payload["metadata"]["name"] == "Test"
    assert payload["entries"]["A"]["name"] == "A"


def test_vocabulary_loader_load_index_empty() -> None:
    assert VocabularyLoader.load_index(None) == {}
    assert VocabularyLoader.load_index({}) == {}


def test_vocabulary_loader_load_index_per_vocab_errors() -> None:
    loaded = VocabularyLoader.load_index(
        {
            "good": {
                "metadata": {"name": "Good", "field": "good"},
                "entries": {"x": {"name": "X"}},
            },
            "bad": {"entries": {}},
        }
    )
    assert "good" in loaded
    assert "bad" not in loaded
