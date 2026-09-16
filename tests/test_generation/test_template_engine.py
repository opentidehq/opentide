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
    resolve_field_schema,
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


def test_gen_template_object_with_properties() -> None:
    metaschema = {
        "metadata": {
            "type": "object",
            "properties": {
                "uuid": {"type": "string"},
                "author": {"type": "string"},
            },
        }
    }
    body = gen_template(metaschema, required=["metadata", "uuid"])
    assert body["metadata"]["uuid"] == "blank"
    assert "#author" in body["metadata"]


def test_gen_template_array_items_optional() -> None:
    metaschema = {
        "signals": {
            "type": "array",
            "items": {
                "properties": {
                    "name": {"type": "string"},
                    "severity": {"type": "string"},
                }
            },
        }
    }
    body = gen_template(metaschema, required=[])
    assert "#signals" in body
    values = body["#signals"][0]
    assert "Comment out name" in values or "name" in values


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


def test_resolve_field_schema_expands_ref_and_nullable_anyof() -> None:
    defs = {
        "ThreatBody": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "att&ck": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["description", "att&ck"],
        },
        "RuleResponse": {
            "type": "object",
            "properties": {"alert_severity": {"type": "string", "default": "Informational"}},
        },
    }
    threat = resolve_field_schema({"$ref": "#/$defs/ThreatBody", "title": "Threat"}, defs)
    assert threat["type"] == "object"
    assert "description" in threat["properties"]
    assert threat["title"] == "Threat"
    missing = resolve_field_schema({"$ref": "#/$defs/Missing", "title": "Keep"}, defs)
    assert missing["title"] == "Keep"
    assert missing["$ref"] == "#/$defs/Missing"
    response = resolve_field_schema(
        {"anyOf": [{"$ref": "#/$defs/RuleResponse"}, {"type": "null"}], "default": None},
        defs,
    )
    assert response["type"] == "object"
    assert "alert_severity" in response["properties"]
    assert response["default"] is None
    oneof = resolve_field_schema(
        {
            "oneOf": [
                "skip-me",
                {"type": "null"},
                {"type": "array", "items": {"type": "string"}},
                {"type": "object", "properties": {"id": {"type": "string"}}},
            ]
        },
        {},
    )
    assert oneof["type"] == "object"
    assert "id" in oneof["properties"]


def test_get_required_walks_ref_nested_required() -> None:
    defs = {
        "ThreatBody": {
            "type": "object",
            "required": ["description", "att&ck"],
            "properties": {
                "description": {"type": "string"},
                "att&ck": {"type": "array"},
            },
        }
    }
    required = get_required(
        {
            "threat": {"$ref": "#/$defs/ThreatBody"},
            "note": "not-a-schema",
        },
        ["threat"],
        defs,
    )
    assert "description" in required
    assert "att&ck" in required
    forced = get_required(
        {
            "metadata": {
                "type": "object",
                "tide.template.force-required": ["uuid"],
                "properties": {"uuid": {"type": "string"}},
            }
        },
        ["metadata"],
    )
    assert "uuid" in forced


def test_gen_template_resolves_ref_nested_object() -> None:
    defs = {
        "ThreatBody": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "att&ck": {"type": "array", "items": {"type": "string"}},
            },
        }
    }
    body = gen_template(
        {"threat": {"$ref": "#/$defs/ThreatBody"}},
        required=["threat", "description"],
        defs=defs,
    )
    assert body["threat"]["description"] == "blank"
    assert "#att&ck" in body["threat"] or "att&ck" in body["threat"]


def test_gen_template_resolves_nullable_anyof_object() -> None:
    defs = {
        "RuleResponse": {
            "type": "object",
            "properties": {
                "alert_severity": {"type": "string", "default": "Informational"},
            },
        }
    }
    body = gen_template(
        {
            "response": {
                "anyOf": [{"$ref": "#/$defs/RuleResponse"}, {"type": "null"}],
                "default": None,
            }
        },
        required=["response"],
        defs=defs,
    )
    nested = body["response"]
    assert nested.get("alert_severity", nested.get("#alert_severity")) == "Informational"


def test_gen_template_resolves_array_item_ref() -> None:
    defs = {
        "DetectionSignal": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "data": {
                    "$ref": "#/$defs/SignalData",
                },
            },
        },
        "SignalData": {
            "type": "object",
            "properties": {"availability": {"type": "string"}},
        },
    }
    body = gen_template(
        {
            "signals": {
                "type": "array",
                "items": {"$ref": "#/$defs/DetectionSignal"},
            }
        },
        required=["signals"],
        defs=defs,
    )
    item = body["signals"][0]
    assert item["name"] == "blank"
    data = item.get("data") or item.get("#data")
    assert data.get("availability", data.get("#availability")) == "blank"


def test_gen_template_recomposition_runs_after_ref_resolve() -> None:
    defs = {
        "RuleConfigurations": {
            "type": "object",
            "additionalProperties": True,
        }
    }
    mock_index = {
        "systems": {
            "sentinel": {"platform": {"enabled": True}},
            "splunk": {"platform": {"enabled": False}},
        }
    }
    with patch("opentide.generation.template_engine.OpenTide") as mock_ot:
        mock_ot.Configurations.Index = mock_index
        body = gen_template(
            {
                "configurations": {
                    "$ref": "#/$defs/RuleConfigurations",
                    "recomposition": "systems",
                }
            },
            required=["configurations"],
            defs=defs,
        )
    assert body["configurations"]["#sentinel"] == "blank"
    assert "#splunk" not in body["configurations"]


def test_gen_template_hides_marked_fields() -> None:
    body = gen_template(
        {
            "name": {"type": "string"},
            "file": {"type": "string", "tide.template.hide": True},
        },
        required=["name"],
    )
    assert "name" in body
    assert "file" not in body
    assert "#file" not in body
