"""Pydantic core model schema generation."""

from __future__ import annotations

from opentide.generation.pydantic_metaschema import core_schema_models
from opentide.generation.pydantic_schemas import generate_core_model_schema


def test_core_schema_models_cover_primary_objects() -> None:
    assert set(core_schema_models()) == {"rule", "objective", "threat"}


def test_generate_core_model_schema_returns_object_schema() -> None:
    schema = generate_core_model_schema("rule", enrich=False)
    assert schema["type"] == "object"
    assert "properties" in schema
    assert schema["properties"]["metadata"]["properties"]["schema"]["const"] == "rule::1.0"
