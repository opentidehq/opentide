"""Schema documentation generation."""

from __future__ import annotations

from opentide.generation.doc_generator import export_schema_docs, generate_model_doc
from opentide.models.rule import DetectionRule


def test_schema_doc_generator_exports_core_models() -> None:
    docs = export_schema_docs()
    assert "rule::1.0" in docs
    assert "objective::1.0" in docs
    assert "threat::1.0" in docs


def test_generate_model_doc_includes_fields() -> None:
    doc = generate_model_doc(DetectionRule)
    assert "rule::1.0" in doc
    assert "**name**" in doc
