"""Tests for inflight change metadata collection from CI environments."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentide.indexing.inflight_change import (
    INFLIGHT_SHARD_SCHEMA,
    build_shard_payload,
    collect_change_metadata,
)


@pytest.fixture
def yaml_path(tmp_path: Path) -> Path:
    path = tmp_path / "objects" / "threats" / "example.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("name: example\n", encoding="utf-8")
    return path


def _clear_ci_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "TF_BUILD",
        "GITHUB_ACTIONS",
        "CI",
        "INFLIGHT_CHANGE_JSON",
    ):
        monkeypatch.delenv(key, raising=False)


def test_github_metadata_from_event_and_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, yaml_path: Path
) -> None:
    event = {
        "pull_request": {
            "number": 116,
            "html_url": "https://github.com/OpenTideHQ/opentide/pull/116",
            "title": "feat(indexing): inflight preview shards",
            "head": {"ref": "feat/inflight-shards", "sha": "from_event_sha"},
            "base": {"ref": "development"},
        }
    }
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event), encoding="utf-8")

    _clear_ci_env(monkeypatch)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_HEAD_REF", "feat/inflight-shards")
    monkeypatch.setenv("GITHUB_BASE_REF", "development")
    monkeypatch.setenv("GITHUB_SHA", "deadbeef")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))

    meta = collect_change_metadata(yaml_path)

    assert meta["platform"] == "github"
    assert meta["number"] == 116
    assert meta["url"] == "https://github.com/OpenTideHQ/opentide/pull/116"
    assert meta["title"] == "feat(indexing): inflight preview shards"
    assert meta["head_ref"] == "feat/inflight-shards"
    assert meta["base_ref"] == "development"
    assert meta["head_sha"] == "deadbeef"
    assert meta["source_path"] == "objects/threats/example.yaml"
    assert "recorded_at" in meta


def test_gitlab_metadata_from_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, yaml_path: Path
) -> None:
    _clear_ci_env(monkeypatch)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "42")
    monkeypatch.setenv("CI_PROJECT_URL", "https://gitlab.com/OpenTideHQ/library")
    monkeypatch.setenv("CI_MERGE_REQUEST_TITLE", "Add inflight example")
    monkeypatch.setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "example/inflight-preview")
    monkeypatch.setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")
    monkeypatch.setenv("CI_COMMIT_SHA", "gitlab_sha")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))

    meta = collect_change_metadata(yaml_path)

    assert meta["platform"] == "gitlab"
    assert meta["number"] == 42
    assert meta["url"] == "https://gitlab.com/OpenTideHQ/library/-/merge_requests/42"
    assert meta["title"] == "Add inflight example"
    assert meta["head_ref"] == "example/inflight-preview"
    assert meta["base_ref"] == "main"
    assert meta["head_sha"] == "gitlab_sha"
    assert meta["source_path"] == "objects/threats/example.yaml"


def test_azure_metadata_from_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, yaml_path: Path
) -> None:
    _clear_ci_env(monkeypatch)
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER", "99")
    monkeypatch.setenv(
        "SYSTEM_PULLREQUEST_PULLREQUESTURI",
        "https://dev.azure.com/org/project/_git/repo/pullrequest/99",
    )
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTTITLE", "Inflight shards")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature/inflight")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_TARGETBRANCH", "refs/heads/main")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "azure_sha")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))

    meta = collect_change_metadata(yaml_path)

    assert meta["platform"] == "azure"
    assert meta["number"] == 99
    assert meta["url"] == "https://dev.azure.com/org/project/_git/repo/pullrequest/99"
    assert meta["title"] == "Inflight shards"
    assert meta["head_ref"] == "feature/inflight"
    assert meta["base_ref"] == "main"
    assert meta["head_sha"] == "azure_sha"


def test_azure_metadata_falls_back_to_pullrequest_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, yaml_path: Path
) -> None:
    _clear_ci_env(monkeypatch)
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "77")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))

    meta = collect_change_metadata(yaml_path)

    assert meta["platform"] == "azure"
    assert meta["number"] == 77


def test_local_metadata_when_no_ci(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, yaml_path: Path
) -> None:
    _clear_ci_env(monkeypatch)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))

    meta = collect_change_metadata(yaml_path)

    assert meta["platform"] == "local"
    assert meta["number"] is None
    assert meta["url"] is None
    assert meta["source_path"] == "objects/threats/example.yaml"


def test_inflight_change_json_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, yaml_path: Path
) -> None:
    _clear_ci_env(monkeypatch)
    monkeypatch.setenv(
        "INFLIGHT_CHANGE_JSON",
        json.dumps({"platform": "github", "number": 1, "title": "override"}),
    )
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))

    meta = collect_change_metadata(yaml_path)

    assert meta["platform"] == "github"
    assert meta["number"] == 1
    assert meta["title"] == "override"
    assert meta["source_path"] == "objects/threats/example.yaml"


def test_build_shard_payload_wraps_object_and_change(yaml_path: Path) -> None:
    body = {
        "name": "Example",
        "metadata": {"uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "schema": "threat::1.0"},
    }

    shard = build_shard_payload(body, yaml_path)

    assert shard["schema"] == INFLIGHT_SHARD_SCHEMA
    assert shard["object"] == body
    assert shard["change"]["platform"] == "local"
    assert "written_at" in shard
