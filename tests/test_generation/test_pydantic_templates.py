"""Pydantic template model generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.generation.pydantic_templates import (
    CORE_TEMPLATE_MODELS,
    core_template_model_keys,
    generate_core_template,
    load_core_template_source,
)


def test_core_template_models_match_schema_models() -> None:
    assert set(CORE_TEMPLATE_MODELS) == {"rule", "objective", "threat"}


def test_load_core_template_source_returns_properties() -> None:
    source = load_core_template_source("rule")
    assert "properties" in source
    assert "required" in source
    assert "$defs" in source


def test_load_core_template_source_unknown_model() -> None:
    with pytest.raises(KeyError, match="not-a-model"):
        load_core_template_source("not-a-model")


def test_core_template_sources_cover_all_models() -> None:
    for key in core_template_model_keys():
        source = load_core_template_source(key)
        assert source["type"] == "object"
        assert source["properties"]


def test_generate_core_template_threat_expands_body(tmp_path: Path) -> None:
    path = tmp_path / "threat.1.0.template.yaml"
    generate_core_template("threat", path)
    text = path.read_text(encoding="utf-8")
    assert "description:" in text
    assert "att&ck:" in text
    after_org = text.split("#organisation:", 1)[1]
    assert "uuid:" in after_org.split("threat:", 1)[0]
    after_threat = text.split("\nthreat:", 1)[1]
    assert "description:" in after_threat
    assert "att&ck:" in after_threat


def test_generate_core_template_objective_expands_composition_and_signals(
    tmp_path: Path,
) -> None:
    path = tmp_path / "objective.1.0.template.yaml"
    generate_core_template("objective", path)
    text = path.read_text(encoding="utf-8")
    assert "strategy:" in text
    assert "signals:" in text or "#signals:" in text
    assert "availability:" in text


def test_generate_core_template_rule_expands_response_and_hides_file(tmp_path: Path) -> None:
    path = tmp_path / "rule.1.0.template.yaml"
    generate_core_template("rule", path)
    text = path.read_text(encoding="utf-8")
    assert "alert_severity:" in text
    assert "file:" not in text
    assert "#file:" not in text
    assert "#platforms:" not in text
    assert "configurations:" in text or "#configurations:" in text
    assert "playbook:" in text
