"""Extended generation vocabulary module coverage."""

from __future__ import annotations

import pytest

from opentide.generation.vocabulary import (
    VocabularyDefinition,
    VocabularyEntry,
    VocabularyLoadError,
    VocabularyMetadata,
    entry_key_field,
    is_id_keyed,
    normalize_stages,
    parse_vocabulary_document,
    parse_yaml_vocabulary,
    resolve_vocab_key,
)


def test_normalize_stages_variants() -> None:
    assert normalize_stages(None) == []
    assert normalize_stages("att&ck") == ["att&ck"]
    assert normalize_stages(["a", "b"]) == ["a", "b"]


def test_resolve_vocab_key_and_entry_key_field() -> None:
    assert resolve_vocab_key({"key": "id"}) == "id"
    assert resolve_vocab_key({"model": True}, source="legacy.toml") == "id"
    assert resolve_vocab_key({}) == "name"
    with pytest.raises(VocabularyLoadError):
        resolve_vocab_key({"key": "invalid"})
    assert entry_key_field(key="id") == "id"
    assert entry_key_field(model=True) == "id"
    assert entry_key_field() == "name"


def test_is_id_keyed_metadata() -> None:
    assert is_id_keyed({"key": "id"}) is True
    assert is_id_keyed({"key": "name"}) is False
    assert is_id_keyed({"model": True}) is True
    assert is_id_keyed({}) is False


def test_vocabulary_metadata_get_and_to_dict() -> None:
    meta = VocabularyMetadata(
        name="Severity",
        field="severity",
        description="Levels",
        key="name",
        stages=[{"id": "core", "name": "Core"}],
        extra={"source": "bundled"},
    )
    assert meta.get("name") == "Severity"
    assert meta.get("source") == "bundled"
    assert meta.get("missing", "default") == "default"
    payload = meta.to_dict()
    assert payload["field"] == "severity"
    assert payload["source"] == "bundled"


def test_vocabulary_entry_as_dict_and_contains() -> None:
    entry = VocabularyEntry(
        name="High",
        description="High severity",
        **{"tide.vocab.stages": "production"},
    )
    data = entry.as_dict()
    assert data["name"] == "High"
    assert "tide.vocab.stages" in data
    assert "name" in entry
    assert entry.get("description") == "High severity"


def test_parse_vocabulary_document_id_keyed_and_duplicates() -> None:
    raw = {
        "name": "Techniques",
        "field": "att&ck",
        "key": "id",
        "keys": [{"name": "Execution", "id": "T1059"}],
    }
    definition = parse_vocabulary_document(raw, source="att&ck.vocab.toml")
    assert isinstance(definition, VocabularyDefinition)
    assert "T1059" in definition.entries

    duplicate = {
        "name": "Dup",
        "field": "severity",
        "keys": [{"name": "A"}, {"name": "A"}],
    }
    with pytest.raises(VocabularyLoadError, match="Duplicate entry key"):
        parse_vocabulary_document(duplicate, source="dup.toml")


def test_parse_vocabulary_document_skips_malformed_entries() -> None:
    raw = {
        "name": "Mixed",
        "field": "tags",
        "keys": ["not-a-mapping", {"name": "Valid"}],
    }
    definition = parse_vocabulary_document(raw, source="mixed.toml")
    assert len(definition.entries) == 1


def test_parse_yaml_vocabulary_alias() -> None:
    raw = {"name": "Alias", "field": "alias", "keys": [{"name": "One"}]}
    assert isinstance(parse_yaml_vocabulary(raw), VocabularyDefinition)


def test_validate_document_structure_errors() -> None:
    with pytest.raises(VocabularyLoadError, match="must be a mapping"):
        parse_vocabulary_document([], source="bad.toml")  # type: ignore[arg-type]
    with pytest.raises(VocabularyLoadError, match="keys' must be a list"):
        parse_vocabulary_document(
            {"name": "X", "field": "x", "keys": "nope"},
            source="bad-keys.toml",
        )
