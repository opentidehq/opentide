"""Extended core I/O tests."""

from __future__ import annotations

import json
from pathlib import Path

from opentide.core.io import dump_yaml, load_json, load_toml, write_text


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
