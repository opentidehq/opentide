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
from opentide.models.threat import ThreatVector_v2_1
from opentide.models.vocab_pins import get_pins


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
        ):
            schema_10 = gen_json_schema(source_10, schema_id="threat::1.0")
            schema_21 = gen_json_schema(source_21, schema_id="threat::2.1")

        enum_10 = schema_10["$defs"]["ThreatBody"]["properties"]["killchain"]["enum"]
        enum_21 = schema_21["$defs"]["ThreatBody"]["properties"]["killchain"]["enum"]
        assert "NewStage" not in enum_10
        assert "NewStage" in enum_21
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
        ):
            schema = generate_schema_for_identifier("threat::2.1")
        killchain_enum = schema["$defs"]["ThreatBody"]["properties"]["killchain"]["enum"]
        assert "NewStage" in killchain_enum
        assert schema["properties"]["metadata"]["properties"]["schema"]["const"] == "threat::2.1"
    finally:
        unregister_model("threat::2.1")
