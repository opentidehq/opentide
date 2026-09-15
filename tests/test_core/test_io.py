"""Unit tests for opentide.core.io helpers."""

from __future__ import annotations

import json
from datetime import date, datetime, time, timezone
from pathlib import Path

import pytest
import yaml

from opentide.core.io import (
    dump_json_text,
    dump_toml,
    dump_yaml,
    json_timestamp_default,
    load_json,
    load_toml,
    load_yaml,
    parse_yaml,
    stringify_yaml_temporals,
    write_text,
    yaml_loader_name,
)


def test_yaml_loader_is_csafe_or_safe() -> None:
    assert yaml_loader_name() in {"CSafeLoader", "SafeLoader"}


def test_load_yaml_roundtrip(tmp_path: Path) -> None:
    payload = {"name": "test", "nested": {"count": 2}}
    path = tmp_path / "data.yaml"
    path.write_text(yaml.dump(payload), encoding="utf-8")
    assert load_yaml(path) == payload


def test_load_json_roundtrip(tmp_path: Path) -> None:
    payload = {"uuid": "abc", "values": [1, 2]}
    path = tmp_path / "data.json"
    path.write_text(dump_json_text(payload), encoding="utf-8")
    assert load_json(path) == payload


def test_load_toml_roundtrip(tmp_path: Path) -> None:
    content = 'title = "MalAPI"\ncount = 3\n'
    path = tmp_path / "data.toml"
    path.write_text(content, encoding="utf-8")
    assert load_toml(path) == {"title": "MalAPI", "count": 3}


def test_dump_toml_roundtrip() -> None:
    assert dump_toml({"title": "MalAPI", "count": 3}) == 'title = "MalAPI"\ncount = 3\n'


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


def test_dump_yaml_accepts_explicit_dumper(tmp_path: Path) -> None:
    from opentide.core.files import IndentFullDumper

    path = tmp_path / "custom.yaml"
    dump_yaml(path, {"list": [{"item": 1}]}, dumper=IndentFullDumper)
    assert "list:" in path.read_text(encoding="utf-8")


def test_load_yaml_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_yaml(tmp_path / "missing.yaml")


def test_parse_yaml_roundtrip() -> None:
    assert parse_yaml("name: alpha\n") == {"name": "alpha"}


def test_parse_yaml_unquoted_dates_are_iso_strings() -> None:
    payload = parse_yaml("metadata:\n  created: 2026-09-11\n  modified: 2026-09-11\n")
    assert payload["metadata"]["created"] == "2026-09-11"
    assert payload["metadata"]["modified"] == "2026-09-11"
    json.dumps(payload)


def test_parse_yaml_quoted_dates_stay_strings() -> None:
    payload = parse_yaml('created: "2026-09-11"\n')
    assert payload["created"] == "2026-09-11"


def test_parse_yaml_timestamps_are_iso_strings() -> None:
    payload = parse_yaml("created: 2026-09-11T12:00:00Z\nwhen: 2026-09-11 12:00:00\n")
    assert payload["created"] == "2026-09-11T12:00:00Z"
    assert payload["when"] == "2026-09-11T12:00:00"


def test_load_yaml_unquoted_dates_are_json_serializable(tmp_path: Path) -> None:
    path = tmp_path / "object.yaml"
    path.write_text("metadata:\n  created: 2026-09-11\n", encoding="utf-8")
    payload = load_yaml(path)
    assert payload["metadata"]["created"] == "2026-09-11"
    json.dumps(payload)


def test_stringify_yaml_temporals_walks_nested_values() -> None:
    nested = {
        date(2026, 9, 11): [
            datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc),
            time(13, 14, 15),
            {"inner": date(2026, 1, 2)},
        ]
    }
    converted = stringify_yaml_temporals(nested)
    assert converted == {
        "2026-09-11": [
            "2026-09-11T12:00:00Z",
            "13:14:15",
            {"inner": "2026-01-02"},
        ]
    }


def test_json_timestamp_default_serializes_dates() -> None:
    assert json_timestamp_default(date(2026, 9, 11)) == "2026-09-11"
    rendered = json.dumps({"created": date(2026, 9, 11)}, default=json_timestamp_default)
    assert json.loads(rendered)["created"] == "2026-09-11"


def test_json_timestamp_default_rejects_unknown_types() -> None:
    with pytest.raises(TypeError, match="object"):
        json_timestamp_default(object())


def test_dump_json_text_supports_default_serializer() -> None:
    rendered = dump_json_text({"when": object()}, default=str)
    assert "object" in rendered
