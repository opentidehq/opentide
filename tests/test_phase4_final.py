"""Phase 4 final — generators, schema store, rule loader tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.generation.doc_generator import export_schema_docs, generate_model_doc
from opentide.generation.schema import TideSchemaGenerator, model_json_schema
from opentide.generation.schema_utils import strip_framework_keywords
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.platform import SentinelConfig
from opentide.models.rule import DetectionRule
from opentide.schemas.store import definitions_path, metaschemas_path, schemas_data_root

ROOT = Path(__file__).resolve().parents[1]


def test_schemas_data_root_exists() -> None:
    root = schemas_data_root()
    assert root.is_dir()
    assert (root / "MDR Meta Schema.yaml").is_file()


def test_metaschemas_path_points_to_bundled_data() -> None:
    assert metaschemas_path().name == "data"
    assert definitions_path().is_dir()


def test_framework_meta_schemas_directory_removed() -> None:
    assert not (ROOT / "Framework/Meta Schemas").exists()


def test_vocabulary_resolver_class_in_opentide() -> None:
    pipeline_source = (ROOT / "src/opentide/generation/schema_pipeline.py").read_text()
    assert "class VocabularyResolver" in pipeline_source
    engines_source = (ROOT / "Engines/framework/json_schemas.py").read_text()
    assert "class EnumResolver" not in engines_source
    assert "class VocabularyResolver" not in engines_source


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


def test_load_rule_from_dict_minimal() -> None:
    payload: dict[str, Any] = {
        "name": "Rule",
        "metadata": {
            "uuid": "00000000-0000-4000-8000-000000000001",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "clear",
        },
        "description": "desc",
        "status": "STAGING",
        "severity": "High",
        "techniques": [],
        "configurations": {
            "sentinel": {
                "enabled": True,
                "name": "S",
                "schema": "platform::sentinel::1.0",
                "status": "STAGING",
            },
        },
    }
    rule = load_rule_from_dict(payload)
    assert isinstance(rule, DetectionRule)
    assert rule.name == "Rule"


def test_schema_doc_generator_exports_core_models() -> None:
    docs = export_schema_docs()
    assert "rule::1.0" in docs
    assert "objective::1.0" in docs
    assert "threat::1.0" in docs


def test_generate_model_doc_includes_fields() -> None:
    doc = generate_model_doc(DetectionRule)
    assert "rule::1.0" in doc
    assert "**name**" in doc


def test_opentide_generation_run_importable() -> None:
    from opentide.generation import schema, template

    assert callable(schema.run)
    assert callable(template.run)
