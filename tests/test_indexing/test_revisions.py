"""Tests for revision index tracking."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from opentide.indexing.revisions import RevisionIndexEntry, RevisionIndexer, RevisionTracker


def _make_indexer(tmp_path: Path, raw_index: dict | None = None) -> RevisionIndexer:
    index_file = tmp_path / "revisions.json"
    index_file.parent.mkdir(parents=True, exist_ok=True)
    index_file.write_text(json.dumps(raw_index or {}), encoding="utf-8")

    rule_uuid = "00000000-0000-4000-8000-000000000020"
    from opentide import OpenTide

    OpenTide._index = {
        "objects": {
            "rule": {
                rule_uuid: {
                    "name": "Sample Rule",
                    "metadata": {"version": 1, "uuid": rule_uuid},
                    "description": "Rule description",
                }
            },
            "threat": {},
            "objective": {},
        },
        "configurations": {
            "global": {
                "objects": ["rule"],
                "indexes": {"revisions": "revisions.json"},
            },
            "documentation": {"object_names": {"rule": "Detection Rule"}},
        },
        "paths": {"tide": {"tide_indexes": str(tmp_path)}},
    }
    OpenTide._initialised = True

    indexer = RevisionIndexer.__new__(RevisionIndexer)
    indexer.INDEX_PATH = index_file
    indexer.OBJECT_SCOPE = OpenTide.Configurations.Global.objects
    indexer.OBJECT_NAMES = OpenTide.Configurations.Documentation.object_names
    indexer.INDEX_NAME = OpenTide.Configurations.Global.indexes.revisions
    indexer.RAW_REVISIONS_INDEX = json.loads(index_file.read_text(encoding="utf-8"))
    indexer.REVISIONS_INDEX = indexer._load_revision_index(indexer.RAW_REVISIONS_INDEX)
    return indexer


def test_load_revision_index_parses_entries() -> None:
    raw = {
        "obj-1": {
            "name": "Rule A",
            "object": "Detection Rule",
            "description": "desc",
            "revisions": {
                "1": {
                    "date": "2026-01-01",
                    "message": "init",
                    "author": "tester",
                    "commit": "abc123",
                }
            },
        }
    }
    indexer = RevisionIndexer.__new__(RevisionIndexer)
    parsed = indexer._load_revision_index(raw)
    assert "obj-1" in parsed
    assert isinstance(parsed["obj-1"], RevisionIndexEntry)
    assert parsed["obj-1"].revisions["1"].author == "tester"


def test_new_revision_uses_git_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    commit = MagicMock(message="feat: update", author="dev", sha="deadbeef")
    monkeypatch.setattr(
        "opentide.indexing.revisions.GitRepository",
        lambda: MagicMock(last_commit_details=commit),
    )
    indexer = RevisionIndexer.__new__(RevisionIndexer)
    tracker = indexer._new_revision()
    assert isinstance(tracker, RevisionTracker)
    assert tracker.commit == "deadbeef"
    assert tracker.message == "feat: update"


def test_create_entry_adds_new_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    commit = MagicMock(message="init", author="dev", sha="abc")
    monkeypatch.setattr(
        "opentide.indexing.revisions.GitRepository",
        lambda: MagicMock(last_commit_details=commit),
    )
    indexer = _make_indexer(tmp_path)
    rule_uuid = "00000000-0000-4000-8000-000000000020"
    entry = indexer._create_entry(rule_uuid, "rule")
    assert entry.name == "Sample Rule"
    assert "1" in entry.revisions


def test_create_entry_reuses_existing_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule_uuid = "00000000-0000-4000-8000-000000000020"
    existing = {
        rule_uuid: {
            "name": "Sample Rule",
            "object": "Detection Rule",
            "description": "Rule description",
            "revisions": {
                "1": {
                    "date": "2026-01-01",
                    "message": "init",
                    "author": "dev",
                    "commit": "abc",
                }
            },
        }
    }
    commit = MagicMock(message="noop", author="dev", sha="def")
    monkeypatch.setattr(
        "opentide.indexing.revisions.GitRepository",
        lambda: MagicMock(last_commit_details=commit),
    )
    indexer = _make_indexer(tmp_path, existing)
    first = indexer._create_entry(rule_uuid, "rule")
    second = indexer._create_entry(rule_uuid, "rule")
    assert first is second
    assert len(second.revisions) == 1


def test_run_exports_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    commit = MagicMock(message="init", author="dev", sha="abc")
    monkeypatch.setattr(
        "opentide.indexing.revisions.GitRepository",
        lambda: MagicMock(last_commit_details=commit),
    )
    indexer = _make_indexer(tmp_path)
    indexer.run()
    exported = json.loads(indexer.INDEX_PATH.read_text(encoding="utf-8"))
    assert "00000000-0000-4000-8000-000000000020" in exported
