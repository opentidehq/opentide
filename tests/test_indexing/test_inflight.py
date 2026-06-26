"""Tests for inflight preview shard generation and registry overlay."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from opentide.indexing.inflight import (
    apply_inflight_overlay,
    load_inflight_shards,
    prune_inflight_shards,
    write_inflight_shards,
)
from opentide.indexing.inflight_change import INFLIGHT_SHARD_SCHEMA, build_shard_payload


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


def _wrap_shard(
    object_body: dict,
    *,
    source_path: str = "objects/threats/example.yaml",
) -> dict:
    return build_shard_payload(object_body, source_path)


@pytest.fixture
def sample_wrapped_shard(sample_threat_body: dict) -> dict:
    return _wrap_shard(sample_threat_body)


def test_write_and_load_inflight_shard(tmp_path: Path, sample_wrapped_shard: dict) -> None:
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
    shard_path.write_text(json.dumps(sample_wrapped_shard), encoding="utf-8")

    shards = load_inflight_shards(inflight_dir)
    assert "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" in shards
    assert shards["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"]["schema"] == INFLIGHT_SHARD_SCHEMA


def test_apply_inflight_overlay_adds_and_updates(sample_wrapped_shard: dict) -> None:
    objects_index: dict = {"threat": {}, "objective": {}, "rule": {}, "signal": {}}
    uuid = sample_wrapped_shard["object"]["metadata"]["uuid"]

    stats = apply_inflight_overlay(objects_index, {uuid: sample_wrapped_shard})
    assert stats["added"] == 1
    assert objects_index["threat"][uuid]["metadata"]["version"] == 2

    older_obj = sample_wrapped_shard["object"].copy()
    older_obj["metadata"] = {**older_obj["metadata"], "version": 1}
    older_shard = _wrap_shard(older_obj)
    stats = apply_inflight_overlay(objects_index, {uuid: older_shard})
    assert stats["updated"] == 0
    assert objects_index["threat"][uuid]["metadata"]["version"] == 2

    newer_obj = sample_wrapped_shard["object"].copy()
    newer_obj["metadata"] = {**newer_obj["metadata"], "version": 3}
    newer_obj["name"] = "Inflight example v3"
    newer_shard = _wrap_shard(newer_obj)
    stats = apply_inflight_overlay(objects_index, {uuid: newer_shard})
    assert stats["updated"] == 1
    assert objects_index["threat"][uuid]["name"] == "Inflight example v3"


def test_apply_inflight_overlay_equal_version_prefers_wrapped_shard() -> None:
    objects_index: dict = {"threat": {}, "objective": {}, "rule": {}, "signal": {}}
    uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    committed = {
        "name": "Committed",
        "metadata": {"uuid": uuid, "schema": "threat::1.0", "version": 2},
        "threat": {"killchain": "Reconnaissance"},
    }
    objects_index["threat"][uuid] = committed

    preview_obj = {
        "name": "Preview",
        "metadata": {"uuid": uuid, "schema": "threat::1.0", "version": 2},
        "threat": {"killchain": "Reconnaissance"},
    }
    preview_shard = _wrap_shard(preview_obj)
    stats = apply_inflight_overlay(objects_index, {uuid: preview_shard})
    assert stats["updated"] == 1
    assert objects_index["threat"][uuid]["name"] == "Preview"


def test_write_inflight_from_yaml(tmp_path: Path, sample_threat_body: dict) -> None:
    yaml_path = tmp_path / "objects" / "threats" / "example.yaml"
    yaml_path.parent.mkdir(parents=True)
    yaml_path.write_text(yaml.dump(sample_threat_body), encoding="utf-8")

    inflight_dir = tmp_path / ".opentide" / "inflight"
    change_meta = {
        "platform": "github",
        "number": 4,
        "url": "https://github.com/OpenTideHQ/library/pull/4",
        "title": "example/inflight-preview",
        "head_ref": "example/inflight-preview",
        "base_ref": "main",
        "head_sha": "abc123",
    }
    os.environ["INFLIGHT_CHANGE_JSON"] = json.dumps(change_meta)
    os.environ["OPENTIDE_REPO_ROOT"] = str(tmp_path)
    try:
        result = write_inflight_shards([yaml_path], inflight_dir=inflight_dir)
    finally:
        os.environ.pop("INFLIGHT_CHANGE_JSON", None)
        os.environ.pop("OPENTIDE_REPO_ROOT", None)

    assert result["count"] == 1
    shard = inflight_dir / "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.json"
    assert shard.is_file()
    loaded = json.loads(shard.read_text(encoding="utf-8"))
    assert loaded["schema"] == INFLIGHT_SHARD_SCHEMA
    assert loaded["object"]["name"] == "Inflight example"
    assert loaded["change"]["platform"] == "github"
    assert loaded["change"]["number"] == 4
    assert loaded["change"]["source_path"] == "objects/threats/example.yaml"


def test_prune_inflight_shard_when_committed_version_catches_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_threat_body: dict
) -> None:
    root = tmp_path
    objects_dir = root / "objects" / "threats"
    objects_dir.mkdir(parents=True)
    yaml_path = objects_dir / "example.yaml"
    yaml_path.write_text(yaml.dump(sample_threat_body), encoding="utf-8")

    inflight_dir = root / ".opentide" / "inflight"
    inflight_dir.mkdir(parents=True)
    shard_path = inflight_dir / "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.json"
    shard_path.write_text(json.dumps(_wrap_shard(sample_threat_body)), encoding="utf-8")

    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(root))
    monkeypatch.setattr(
        "opentide.indexing.inflight.resolve_workspace_paths",
        lambda: {
            "threat": objects_dir,
            "objective": root / "objects" / "objectives",
            "rule": root / "objects" / "rules",
            "inflight": inflight_dir,
        },
    )

    result = prune_inflight_shards(inflight_dir=inflight_dir)
    assert result["count"] == 1
    assert not shard_path.exists()


def test_legacy_raw_shard_still_overlays(sample_threat_body: dict) -> None:
    objects_index: dict = {"threat": {}, "objective": {}, "rule": {}, "signal": {}}
    uuid = sample_threat_body["metadata"]["uuid"]
    stats = apply_inflight_overlay(objects_index, {uuid: sample_threat_body})
    assert stats["added"] == 1
