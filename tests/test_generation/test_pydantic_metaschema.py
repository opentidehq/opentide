"""Tests for pydantic metaschema generation."""

from __future__ import annotations

from opentide.generation import pydantic_metaschema as meta
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector


def test_build_definition_index_contains_metadata() -> None:
    index = meta.build_definition_index()
    assert "metadata" in index


def test_build_core_schema_source_rule() -> None:
    schema = meta.build_core_schema_source("rule")
    assert schema["title"] == "Detection Rule Schema"


def test_build_model_schema_source() -> None:
    schema = meta.build_model_schema_source(DetectionRule)
    assert "properties" in schema


def test_build_platform_schema_source() -> None:
    schema = meta.build_platform_schema_source(DetectionRule)
    assert isinstance(schema, dict)


def test_lookup_schema_extra_missing_returns_none() -> None:
    schema = {"properties": {"name": {"type": "string"}}}
    assert meta.lookup_schema_extra(schema, "missing", "tide.vocab") is None


def test_core_schema_models_keys() -> None:
    assert set(meta.CORE_SCHEMA_MODELS) == {"rule", "objective", "threat"}
    assert meta.CORE_SCHEMA_MODELS["rule"] is DetectionRule
    assert meta.CORE_SCHEMA_MODELS["objective"] is DetectionObjective
    assert meta.CORE_SCHEMA_MODELS["threat"] is ThreatVector
