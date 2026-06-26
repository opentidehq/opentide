"""Tests for generation pydantic schema output module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from opentide.generation import pydantic_schemas


def test_generate_core_model_schema_enriched() -> None:
    with (
        patch(
            "opentide.generation.pydantic_metaschema.build_schema_source_for_identifier",
            return_value={"type": "object", "properties": {}},
        ),
        patch(
            "opentide.generation.schema_pipeline.gen_json_schema",
            side_effect=lambda schema, schema_id=None: schema,
        ),
    ):
        schema = pydantic_schemas.generate_core_model_schema("rule")
    assert schema["type"] == "object"


def test_export_core_model_schema_writes_file(tmp_path: Path) -> None:
    output = tmp_path / "rule.schema.json"
    with patch(
        "opentide.generation.pydantic_schemas.generate_schema_for_identifier",
        return_value={"title": "Rule"},
    ):
        pydantic_schemas.export_core_model_schema("rule", output)
    assert output.is_file()
    assert "Rule" in output.read_text(encoding="utf-8")


def test_export_all_core_model_schemas(tmp_path: Path) -> None:
    with patch(
        "opentide.generation.pydantic_schemas.export_schema_for_identifier",
    ) as mock_export:
        pydantic_schemas.export_all_core_model_schemas(
            json_schema_folder=tmp_path,
            json_schema_map={"rule::1.0": "rule.json"},
        )
    assert mock_export.call_count >= 1
