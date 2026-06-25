"""Extended core I/O tests."""

from __future__ import annotations

import json
from pathlib import Path

from opentide.core.io import (
    dump_json,
    dump_json_text,
    dump_yaml,
    load_json,
    load_toml,
    parse_json,
    write_text,
)


def test_load_json_and_toml(tmp_path: Path) -> None:
    json_path = tmp_path / "data.json"
    json_path.write_text(json.dumps({"a": 1}), encoding="utf-8")
    toml_path = tmp_path / "data.toml"
    toml_path.write_text('key = "value"\n', encoding="utf-8")
    assert load_json(json_path)["a"] == 1
    assert load_toml(toml_path)["key"] == "value"


def test_dump_yaml_writes_file(tmp_path: Path) -> None:
    path = tmp_path / "out.yaml"
    dump_yaml(path, {"name": "test"})
    assert "name:" in path.read_text(encoding="utf-8")


def test_write_text_creates_parents(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "file.txt"
    write_text(path, "hello")
    assert path.read_text(encoding="utf-8") == "hello"


def test_parse_json_accepts_text() -> None:
    assert parse_json('{"enabled": true}')["enabled"] is True


def test_parse_json_accepts_bytes() -> None:
    assert parse_json(b'{"enabled": false}')["enabled"] is False


def test_dump_json_can_omit_trailing_newline() -> None:
    payload = dump_json({"a": 1}, append_newline=False)
    assert payload == b'{"a":1}'


def test_dump_json_text_matches_dump_json() -> None:
    assert dump_json_text({"x": 2}, indent=True).startswith("{\n")


def test_dump_json_supports_default_serializer() -> None:
    payload = dump_json({"ts": object()}, default=str, append_newline=False)
    assert b"object" in payload
