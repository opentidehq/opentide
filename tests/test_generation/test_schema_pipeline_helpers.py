"""Tests for schema pipeline pure helpers."""

from __future__ import annotations

from opentide.generation import schema_pipeline


def test_strip_framework_keywords_removes_tide_keys() -> None:
    payload = {
        "title": "Rule",
        "tide.vocab": "severity",
        "nested": {"tide.template.hide": True, "type": "string"},
    }
    cleaned = schema_pipeline.strip_framework_keywords(payload)
    assert "tide.vocab" not in cleaned
    assert cleaned["title"] == "Rule"
    assert "tide.template.hide" not in cleaned["nested"]
    assert cleaned["nested"]["type"] == "string"


def test_gen_json_schema_passes_through_simple_schema() -> None:
    result = schema_pipeline.gen_json_schema({"type": "object", "properties": {}})
    assert result["type"] == "object"
