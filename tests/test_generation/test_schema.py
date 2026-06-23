"""Schema generation utilities."""

from __future__ import annotations

from opentide.generation.schema import TideSchemaGenerator, model_json_schema
from opentide.generation.schema_utils import strip_framework_keywords
from opentide.models.platform import SentinelConfig


def test_strip_framework_keywords_removes_tide_keys() -> None:
    payload = {"title": "x", "tide.vocab": True, "nested": {"tide.hide": True, "type": "string"}}
    cleaned = strip_framework_keywords(payload)
    assert "tide.vocab" not in cleaned
    assert "tide.hide" not in cleaned["nested"]
    assert cleaned["nested"]["type"] == "string"


def test_tide_schema_generator_for_platform_model() -> None:
    schema = model_json_schema(SentinelConfig)
    assert schema["type"] == "object"
    assert isinstance(TideSchemaGenerator, type)


def test_tide_schema_generator_model_json_schema() -> None:
    schema = model_json_schema(SentinelConfig)
    assert schema["type"] == "object"
    assert "properties" in schema


def test_opentide_generation_run_importable() -> None:
    from opentide.generation import schema, template

    assert callable(schema.run)
    assert callable(template.run)
