"""Typed vocabulary loader behaviour."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentide.core.files import resolve_paths
from opentide.generation.vocabulary import (
    VocabularyDefinition,
    VocabularyEntry,
    VocabularyLoader,
    VocabularyLoadError,
    VocabularyMetadata,
    entry_key_field,
    is_id_keyed,
    normalize_stages,
    parse_vocabulary_document,
    parse_yaml_vocabulary,
    resolve_vocab_key,
)
from opentide.vocabulary.io import (
    field_from_vocab_path,
    load_vocab_file,
    strip_spurious_entry_id,
    validate_field_matches_path,
    write_vocab_file,
)
from opentide.vocabulary.stix_attack import load_stix_bundle, parse_techniques


@pytest.mark.parametrize(
    ("stages", "expected"),
    [
        (None, []),
        ("OS", ["OS"]),
        (["OS", "Cloud"], ["OS", "Cloud"]),
    ],
)
def test_normalize_stages(stages: str | list[str] | None, expected: list[str]) -> None:
    assert normalize_stages(stages) == expected


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"key": "id"}, "id"),
        ({"key": "name"}, "name"),
        ({"model": True}, "id"),
        ({"model": False}, "name"),
    ],
)
def test_entry_key_field(kwargs: dict[str, object], expected: str) -> None:
    assert entry_key_field(**kwargs) == expected


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        ({"key": "id"}, "id"),
        ({"key": "name"}, "name"),
        ({"model": True}, "id"),
        ({}, "name"),
    ],
)
def test_resolve_vocab_key(metadata: dict[str, object], expected: str) -> None:
    assert resolve_vocab_key(metadata) == expected


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        ({"key": "id"}, True),
        ({"key": "name"}, False),
        ({"model": True}, True),
    ],
)
def test_is_id_keyed(metadata: dict[str, object], expected: bool) -> None:
    assert is_id_keyed(metadata) is expected


def test_vocabulary_loader_load_valid() -> None:
    raw = {
        "metadata": {
            "name": "Impact",
            "field": "impact",
            "description": "Impact levels",
            "icon": "",
            "key": "name",
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
        "metadata": {"name": "Test", "field": "test", "key": "name"},
        "entries": {
            "good": {"name": "Good"},
            "bad": "not-a-mapping",
        },
    }
    vocabulary = VocabularyLoader.load(raw, source="test")
    assert "good" in vocabulary.entries
    assert "bad" not in vocabulary.entries


def test_parse_vocabulary_document() -> None:
    raw = {
        "name": "Severity",
        "field": "severity",
        "description": "Severity scale",
        "keys": [
            {"name": "Low", "description": "Low severity"},
            {"name": "High", "description": "High severity", "tide.vocab.stages": ["A", "B"]},
        ],
    }
    vocabulary = parse_vocabulary_document(raw, source="severity.vocab.toml")
    assert vocabulary.metadata.field == "severity"
    assert vocabulary.metadata.key == "name"
    assert vocabulary.entries["Low"].description == "Low severity"
    assert vocabulary.entries["High"].stages == ("A", "B")


def test_parse_vocabulary_document_id_keyed() -> None:
    raw = {
        "name": "Rules",
        "field": "rule",
        "model": True,
        "keys": [{"id": "uuid-1", "name": "Rule One"}],
    }
    vocabulary = parse_vocabulary_document(raw, source="rules.vocab.toml")
    assert "uuid-1" in vocabulary.entries
    assert vocabulary.entries["uuid-1"].name == "Rule One"


def test_parse_vocabulary_document_duplicate_id_raises() -> None:
    raw = {
        "name": "Test",
        "field": "test",
        "key": "id",
        "keys": [
            {"id": "T1", "name": "One"},
            {"id": "T1", "name": "Duplicate"},
        ],
    }
    with pytest.raises(VocabularyLoadError, match="Duplicate entry key"):
        parse_vocabulary_document(raw, source="test.vocab.toml")


def test_parse_vocabulary_document_empty_keys_allowed() -> None:
    raw = {
        "name": "Responders",
        "field": "responders",
        "description": "Instance-defined",
        "keys": [],
    }
    vocabulary = parse_vocabulary_document(raw, source="responders.vocab.toml")
    assert vocabulary.metadata.field == "responders"
    assert vocabulary.entries == {}


def test_parse_vocabulary_document_missing_required() -> None:
    with pytest.raises(VocabularyLoadError, match="Missing required key 'field'"):
        parse_vocabulary_document({"name": "X"}, source="bad.vocab.toml")


def test_parse_vocabulary_document_no_keys_defaults_empty() -> None:
    vocabulary = parse_vocabulary_document(
        {"name": "Responders", "field": "responders"},
        source="responders.vocab.toml",
    )
    assert vocabulary.entries == {}


def test_parse_yaml_vocabulary_alias() -> None:
    raw = {"name": "X", "field": "x", "keys": [{"name": "A"}]}
    vocabulary = parse_yaml_vocabulary(raw, source="x.yaml")
    assert "A" in vocabulary.entries


def test_vocabulary_entry_as_dict_roundtrip() -> None:
    entry = VocabularyEntry(
        name="Windows",
        description="Microsoft Windows",
        icon="",
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
                "metadata": {"name": "Good", "field": "good", "key": "name"},
                "entries": {"x": {"name": "X"}},
            },
            "bad": {"entries": {}},
        }
    )
    assert "good" in loaded
    assert "bad" not in loaded


def test_field_from_vocab_path() -> None:
    assert field_from_vocab_path(Path("surface.vocab.toml")) == "surface"
    assert field_from_vocab_path(Path("att&ck.groups.vocab.toml")) == "att&ck.groups"


def test_validate_field_matches_path() -> None:
    with pytest.raises(VocabularyLoadError, match="does not match filename"):
        validate_field_matches_path({"field": "wrong"}, Path("impact.vocab.toml"))


def test_strip_spurious_entry_id() -> None:
    entry = {"id": "IMP0001", "name": "Nuisance"}
    cleaned = strip_spurious_entry_id(entry, vocab_key="name", field="impact")
    assert "id" not in cleaned


def test_load_vocab_file_roundtrip(tmp_path: Path) -> None:
    doc = {
        "name": "Impact",
        "field": "impact",
        "key": "name",
        "keys": [{"name": "Nuisance", "description": "Small"}],
    }
    path = tmp_path / "impact.vocab.toml"
    write_vocab_file(path, doc)
    vocabulary = load_vocab_file(path)
    assert vocabulary.metadata.field == "impact"
    assert vocabulary.entries["Nuisance"].description == "Small"


def test_load_bundled_impact_vocab() -> None:
    vocab_path = Path(resolve_paths()["vocabularies"]) / "impact.vocab.toml"
    vocabulary = load_vocab_file(vocab_path)
    assert "Nuisance" in vocabulary.entries
    assert "id" not in vocabulary.entries["Nuisance"].extra


def test_stix_parse_techniques_fixture(tmp_path: Path) -> None:
    fixture = {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "name": "Defense Evasion",
                "x_mitre_shortname": "defense-evasion",
            },
            {
                "type": "attack-pattern",
                "name": "Abuse Elevation Control Mechanism",
                "description": "Test technique",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1548",
                        "url": "https://attack.mitre.org/techniques/T1548",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
                ],
            },
        ],
    }
    bundle_path = tmp_path / "enterprise-attack.json"
    bundle_path.write_text(json.dumps(fixture), encoding="utf-8")
    objects = load_stix_bundle(bundle_path)
    techniques = parse_techniques(objects)
    assert len(techniques) == 1
    assert techniques[0]["id"] == "T1548"
    assert techniques[0]["name"] == "Abuse Elevation Control Mechanism"
    assert "Defense Evasion" in techniques[0]["tide.vocab.stages"]


def test_parse_vocabulary_document_skips_malformed_entries() -> None:
    raw = {
        "name": "Test",
        "field": "test",
        "key": "name",
        "keys": [
            {"name": "Good"},
            "bad-entry",
            {"description": "missing name"},
        ],
    }
    vocabulary = parse_vocabulary_document(raw, source="test.vocab.toml")
    assert list(vocabulary.entries) == ["Good"]
