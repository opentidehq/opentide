"""Unit tests for opentide.core.io helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from opentide.core.io import dump_yaml, load_json, load_toml, load_yaml, write_text


def test_load_yaml_roundtrip(tmp_path: Path) -> None:
    payload = {"name": "test", "nested": {"count": 2}}
    path = tmp_path / "data.yaml"
    path.write_text(yaml.dump(payload), encoding="utf-8")
    assert load_yaml(path) == payload


def test_load_json_roundtrip(tmp_path: Path) -> None:
    payload = {"uuid": "abc", "values": [1, 2]}
    path = tmp_path / "data.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_json(path) == payload


def test_load_toml_roundtrip(tmp_path: Path) -> None:
    content = 'title = "MalAPI"\ncount = 3\n'
    path = tmp_path / "data.toml"
    path.write_text(content, encoding="utf-8")
    assert load_toml(path) == {"title": "MalAPI", "count": 3}


def test_write_text_creates_parent_dirs(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "file.txt"
    write_text(path, "hello")
    assert path.read_text(encoding="utf-8") == "hello"


def test_dump_yaml_writes_mapping(tmp_path: Path) -> None:
    path = tmp_path / "out" / "config.yaml"
    dump_yaml(path, {"alpha": 1, "beta": {"gamma": True}})
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["alpha"] == 1
    assert loaded["beta"]["gamma"] is True


def test_load_yaml_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_yaml(tmp_path / "missing.yaml")
