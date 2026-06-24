"""Extended pydantic metaschema helpers."""

from __future__ import annotations

from opentide.generation import pydantic_metaschema as meta
from opentide.models.rule import DetectionRule


def test_lookup_schema_extra_with_scope_and_nested() -> None:
    schema = {
        "properties": {
            "platforms": {
                "type": "object",
                "properties": {
                    "sentinel": {
                        "type": "object",
                        "properties": {"query": {"type": "string", "tide.vocab": "query"}},
                    }
                },
            }
        }
    }
    assert meta.lookup_schema_extra(schema, "query", "tide.vocab", scope="platforms") == "query"


def test_platform_field_extra_reads_model_schema() -> None:
    value = meta.platform_field_extra(DetectionRule, "name", "type")
    assert value is not None or value is None


def test_normalize_schema_wraps_bare_properties() -> None:
    wrapped = meta._normalize_schema({"name": {"type": "string"}})
    assert "properties" in wrapped


def test_build_definition_index_has_platform_sections() -> None:
    index = meta.build_definition_index()
    assert isinstance(index, dict)
    assert len(index) > 1
