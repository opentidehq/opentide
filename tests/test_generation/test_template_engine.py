"""Tests for template emission engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from opentide.generation.template_engine import (
    fetch_config_template,
    gen_template,
    get_required,
    indent_template,
    make_spaces,
    remove_blanks,
    replace_strings_in_file,
)


def test_fetch_config_template_resolves_dot_path() -> None:
    mock_index = {"global": {"objects": ["rule", "threat"]}}
    with patch("opentide.generation.template_engine.OpenTide") as mock_ot:
        mock_ot.Configurations.Index = mock_index
        assert fetch_config_template("global.objects") == "['rule', 'threat']"


def test_fetch_config_template_missing_key_returns_empty() -> None:
    with patch("opentide.generation.template_engine.OpenTide") as mock_ot:
        mock_ot.Configurations.Index = {"global": {}}
        assert fetch_config_template("global.missing") == ""


def test_get_required_collects_nested_fields() -> None:
    metaschema = {
        "metadata": {
            "type": "object",
            "required": ["uuid"],
            "properties": {"uuid": {"type": "string"}},
        }
    }
    required = get_required(metaschema, ["metadata"])
    assert "uuid" in required


def test_gen_template_simple_string_field() -> None:
    metaschema = {"name": {"type": "string"}}
    body = gen_template(metaschema, required=["name"])
    assert body["name"] == "blank"


def test_gen_template_optional_field_commented() -> None:
    metaschema = {"description": {"type": "string"}}
    body = gen_template(metaschema, required=[])
    assert "#description" in body


def test_replace_strings_in_file(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("key: blank\nother: Comment out\n", encoding="utf-8")
    replace_strings_in_file(path, ["blank"], "filled")
    content = path.read_text(encoding="utf-8")
    assert "filled" in content
    assert "blank" not in content


def test_remove_blanks(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("key: value\n\n\nother: x\n", encoding="utf-8")
    remove_blanks(path)
    assert path.read_text(encoding="utf-8") == "key: value\nother: x\n"


def test_indent_template(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("key: value\n", encoding="utf-8")
    indent_template(path, 4)
    assert path.read_text(encoding="utf-8").startswith("    key:")


def test_make_spaces_adds_blank_line(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("metadata:\n  uuid: blank\n", encoding="utf-8")
    metaschema = {"metadata": {"type": "object", "tide.template.spacer": True}}
    monkeypatch.setattr(
        "opentide.generation.pydantic_metaschema.lookup_schema_extra",
        lambda _schema, key, attr, scope=None: True if attr == "tide.template.spacer" else "object",
    )
    make_spaces(path, metaschema)
    content = path.read_text(encoding="utf-8")
    assert content.startswith("\n") or "\nmetadata:" in content
