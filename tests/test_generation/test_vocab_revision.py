"""Tests for vocabulary revision filtering and pin application."""

from __future__ import annotations

from opentide.generation.pydantic_metaschema import (
    apply_vocab_pins,
    build_schema_source_for_identifier,
)
from opentide.generation.pydantic_schemas import generate_schema_for_identifier
from opentide.generation.schema_pipeline import gen_json_schema
from opentide.generation.vocabulary import (
    VocabularyDefinition,
    VocabularyEntry,
    VocabularyMetadata,
    VocabularyRevisionResolver,
)
from opentide.models.schema_registry import register_model, unregister_model
from opentide.models.threat import ThreatVector
from opentide.models.vocab_pins import get_pins


class ThreatVector_v2_1(ThreatVector):
    """Test-only registration. ``threat::2.1`` is not a shipped model."""

    __schema_identifier__ = "threat::2.1"


def _union_string_enum(node: dict) -> list:
    if "enum" in node:
        return node["enum"]
    for alternative in node.get("anyOf") or node.get("oneOf") or []:
        if alternative.get("type") == "string" and "enum" in alternative:
            return alternative["enum"]
    raise KeyError("enum")


def _union_array_enum(node: dict) -> list:
    for alternative in node.get("anyOf") or node.get("oneOf") or []:
        if alternative.get("type") == "array":
            return alternative["items"]["enum"]
    return node["items"]["enum"]


def _killchain_vocab() -> VocabularyDefinition:
    return VocabularyDefinition(
        metadata=VocabularyMetadata(name="Kill Chain", field="killchain", key="name"),
        entries={
            "Reconnaissance": VocabularyEntry(name="Reconnaissance", version="1.0"),
            "NewStage": VocabularyEntry(name="NewStage", version="1.1"),
            "Retired": VocabularyEntry(name="Retired", version="1.0", removed="1.1"),
        },
    )


def test_cumulative_minor_filter_includes_newer_keys() -> None:
    vocab = _killchain_vocab()
    at_10 = VocabularyRevisionResolver.filter_entries(vocab, "killchain::1.0")
    at_11 = VocabularyRevisionResolver.filter_entries(vocab, "killchain::1.1")
    assert "Reconnaissance" in at_10
    assert "NewStage" not in at_10
    assert "NewStage" in at_11


def test_removed_key_excluded_at_and_after_removal_pin() -> None:
    vocab = _killchain_vocab()
    at_10 = VocabularyRevisionResolver.filter_entries(vocab, "killchain::1.0")
    at_11 = VocabularyRevisionResolver.filter_entries(vocab, "killchain::1.1")
    assert "Retired" in at_10
    assert "Retired" not in at_11


def test_apply_vocab_pins_sets_nested_contracts() -> None:
    schema: dict = {
        "properties": {
            "metadata": {"$ref": "#/$defs/ObjectMetadata"},
            "threat": {"$ref": "#/$defs/ThreatBody"},
        },
        "$defs": {
            "ObjectMetadata": {"type": "object", "properties": {"tlp": {"type": "string"}}},
            "ThreatBody": {
                "type": "object",
                "properties": {"killchain": {"type": "string"}},
            },
        },
    }
    apply_vocab_pins(schema, "threat::2.1")
    assert schema["$defs"]["ObjectMetadata"]["properties"]["tlp"]["tide.vocab"] == "tlp::1.0"
    assert (
        schema["$defs"]["ThreatBody"]["properties"]["killchain"]["tide.vocab"] == "killchain::1.1"
    )


def test_get_pins_for_threat_revisions_differ_on_killchain() -> None:
    pins_10 = get_pins("threat::1.0")
    pins_21 = get_pins("threat::2.1")
    assert pins_10["threat.killchain"] == "killchain::1.0"
    assert pins_21["threat.killchain"] == "killchain::1.1"
    assert pins_10["threat.actors.name"] == "actors::1.0"
    assert pins_21["threat.actors.name"] == "actors::1.0"
    assert "threat.actors" not in pins_10
    assert "threat.actors" not in pins_21


def test_threat_schema_pins_actors_name_on_object_items() -> None:
    source = build_schema_source_for_identifier("threat::1.0")
    actor = source["$defs"]["ThreatActor"]["properties"]["name"]
    assert actor["tide.vocab"] == "actors::1.0"
    assert actor.get("tide.vocab.scoped") is True
    actors_field = source["$defs"]["ThreatBody"]["properties"]["actors"]
    assert "tide.vocab" not in actors_field
    cve_field = source["$defs"]["ThreatBody"]["properties"]["cve"]
    assert cve_field.get("title") == "CVE"


def test_threat_schema_identifiers_compile_different_killchain_enums() -> None:
    from unittest.mock import patch

    from opentide.generation import schema_pipeline as sp

    register_model(ThreatVector_v2_1)
    try:
        vocab = _killchain_vocab()
        source_10 = build_schema_source_for_identifier("threat::1.0")
        source_21 = build_schema_source_for_identifier("threat::2.1")

        with (
            patch.object(sp, "VOCAB_INDEX", {"killchain": vocab}),
            patch.object(sp, "VOCAB_EXTENSIONS", {}),
            patch.object(sp, "OBJECT_TYPES", []),
            patch.object(sp, "_runtime_ready", True),
        ):
            schema_10 = gen_json_schema(source_10, schema_id="threat::1.0")
            schema_21 = gen_json_schema(source_21, schema_id="threat::2.1")

        enum_10 = _union_string_enum(schema_10["$defs"]["ThreatBody"]["properties"]["killchain"])
        enum_21 = _union_string_enum(schema_21["$defs"]["ThreatBody"]["properties"]["killchain"])
        assert "NewStage" not in enum_10
        assert "NewStage" in enum_21
        array_21 = _union_array_enum(schema_21["$defs"]["ThreatBody"]["properties"]["killchain"])
        assert "NewStage" in array_21
    finally:
        unregister_model("threat::2.1")


def test_generate_schema_for_identifier_uses_registered_revision() -> None:
    from unittest.mock import patch

    from opentide.generation import schema_pipeline as sp

    register_model(ThreatVector_v2_1)
    try:
        vocab = _killchain_vocab()
        with (
            patch.object(sp, "VOCAB_INDEX", {"killchain": vocab}),
            patch.object(sp, "VOCAB_EXTENSIONS", {}),
            patch.object(sp, "OBJECT_TYPES", []),
            patch.object(sp, "_runtime_ready", True),
        ):
            schema = generate_schema_for_identifier("threat::2.1")
        killchain = schema["$defs"]["ThreatBody"]["properties"]["killchain"]
        assert "NewStage" in _union_string_enum(killchain)
        assert "NewStage" in _union_array_enum(killchain)
        assert schema["properties"]["metadata"]["properties"]["schema"]["const"] == "threat::2.1"
    finally:
        unregister_model("threat::2.1")
