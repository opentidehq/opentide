"""Pydantic template model generation."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

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


def test_generate_core_template_unknown_model(tmp_path: Path) -> None:
    with pytest.raises(KeyError, match="not-a-model"):
        generate_core_template("not-a-model", tmp_path / "x.yaml")


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
    after_org = text.split("#organisation:", 1)[1].split("threat:", 1)[0]
    assert "#  uuid:" in after_org
    assert "#  name:" in after_org
    assert "\n    uuid:" not in after_org
    assert "\n    name:" not in after_org
    loaded = yaml.safe_load(text)
    tlp = loaded["metadata"]["tlp"]
    assert tlp in (None, "")
    assert not isinstance(tlp, dict)
    assert "organisation" not in loaded["metadata"]
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
    after_data = text.split("data:", 1)[1].split("methodology:", 1)[0]
    assert "availability:" in after_data
    assert "requirements:" in after_data
    assert "#availability:" not in after_data
    assert "#requirements:" not in after_data
    assert "#logsources:" in after_data


def test_generate_core_template_rule_expands_response_and_hides_file(tmp_path: Path) -> None:
    path = tmp_path / "rule.1.0.template.yaml"
    generate_core_template("rule", path)
    text = path.read_text(encoding="utf-8")
    assert "alert_severity:" in text
    assert re.search(r"(?m)^[ ]*#?file:", text) is None
    assert "#platforms:" not in text
    assert "configurations:" in text or "#configurations:" in text
    assert "playbook:" in text
    loaded = yaml.safe_load(text)
    response = loaded.get("response") or {}
    assert "analysis" not in response
    assert "procedure" not in response


def test_generate_core_templates_never_emit_yaml_null(tmp_path: Path) -> None:
    for key in core_template_model_keys():
        path = tmp_path / f"{key}.template.yaml"
        generate_core_template(key, path)
        text = path.read_text(encoding="utf-8")
        assert "null" not in text, key
        assert "created: YYYY-MM-DD" in text
        assert "#author:" in text
        assert "#author: null" not in text


def test_generate_core_template_threat_nested_description_is_multiline(tmp_path: Path) -> None:
    path = tmp_path / "threat.1.0.template.yaml"
    generate_core_template("threat", path)
    text = path.read_text(encoding="utf-8")
    after_threat = text.split("\nthreat:", 1)[1]
    assert "description: |" in after_threat
    assert "..." in after_threat
