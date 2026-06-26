"""Tests for inflight preview shard generation and registry overlay."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentide.indexing.inflight import (
    apply_inflight_overlay,
    load_inflight_shards,
    write_inflight_shards,
)


@pytest.fixture
def sample_threat_body() -> dict:
    return {
        "name": "Inflight example",
        "metadata": {
            "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "schema": "threat::1.0",
            "version": 2,
            "tlp": "clear",
        },
        "threat": {"description": "preview", "killchain": "Reconnaissance"},
    }


def test_write_and_load_inflight_shard(tmp_path: Path, sample_threat_body: dict) -> None:
    yaml_path = tmp_path / "objects" / "threats" / "example.yaml"
    yaml_path.parent.mkdir(parents=True)
    yaml_path.write_text("name: example\n", encoding="utf-8")

    inflight_dir = tmp_path / ".opentide" / "inflight"
    result = write_inflight_shards(
        [yaml_path],
        inflight_dir=inflight_dir,
    )
    assert result["count"] == 0  # empty yaml has no uuid

    shard_path = inflight_dir / "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.json"
    shard_path.write_text(json.dumps(sample_threat_body), encoding="utf-8")

    shards = load_inflight_shards(inflight_dir)
    assert "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" in shards


def test_apply_inflight_overlay_adds_and_updates(sample_threat_body: dict) -> None:
    objects_index: dict = {"threat": {}, "objective": {}, "rule": {}, "signal": {}}
    uuid = sample_threat_body["metadata"]["uuid"]

    stats = apply_inflight_overlay(objects_index, {uuid: sample_threat_body})
    assert stats["added"] == 1
    assert objects_index["threat"][uuid]["metadata"]["version"] == 2

    older = sample_threat_body.copy()
    older["metadata"] = {**sample_threat_body["metadata"], "version": 1}
    stats = apply_inflight_overlay(objects_index, {uuid: older})
    assert stats["updated"] == 0
    assert objects_index["threat"][uuid]["metadata"]["version"] == 2

    newer = sample_threat_body.copy()
    newer["metadata"] = {**sample_threat_body["metadata"], "version": 3}
    newer["name"] = "Inflight example v3"
    stats = apply_inflight_overlay(objects_index, {uuid: newer})
    assert stats["updated"] == 1
    assert objects_index["threat"][uuid]["name"] == "Inflight example v3"


def test_write_inflight_from_yaml(tmp_path: Path, sample_threat_body: dict) -> None:
    import yaml

    yaml_path = tmp_path / "objects" / "threats" / "example.yaml"
    yaml_path.parent.mkdir(parents=True)
    yaml_path.write_text(yaml.dump(sample_threat_body), encoding="utf-8")

    inflight_dir = tmp_path / ".opentide" / "inflight"
    result = write_inflight_shards([yaml_path], inflight_dir=inflight_dir)
    assert result["count"] == 1
    shard = inflight_dir / "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.json"
    assert shard.is_file()
    loaded = json.loads(shard.read_text(encoding="utf-8"))
    assert loaded["name"] == "Inflight example"
