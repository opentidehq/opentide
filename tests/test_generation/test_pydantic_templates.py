"""Pydantic template model generation."""

from __future__ import annotations

from opentide.generation.pydantic_templates import (
    CORE_TEMPLATE_MODELS,
    core_metaschema_path,
    core_template_model_keys,
    load_core_template_source,
)


def test_core_template_models_match_schema_models() -> None:
    assert set(CORE_TEMPLATE_MODELS) == {"mdr", "dom", "tvm"}


def test_load_core_template_source_returns_properties() -> None:
    source = load_core_template_source("mdr")
    assert "properties" in source
    assert "required" in source


def test_core_metaschema_paths_exist() -> None:
    for key in core_template_model_keys():
        assert core_metaschema_path(key).is_file()
