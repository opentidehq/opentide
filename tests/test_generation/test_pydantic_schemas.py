"""Pydantic core model schema generation."""

from __future__ import annotations

from opentide.generation.pydantic_metaschema import CORE_SCHEMA_MODELS
from opentide.generation.pydantic_schemas import generate_core_model_schema


def test_core_schema_models_cover_primary_objects() -> None:
    assert set(CORE_SCHEMA_MODELS) == {"mdr", "dom", "tvm"}


def test_generate_core_model_schema_returns_object_schema() -> None:
    schema = generate_core_model_schema("mdr", enrich=False)
    assert schema["type"] == "object"
    assert "properties" in schema
