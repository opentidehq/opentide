"""Tests for vocabulary sync/check maintainer script."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_MODULE = Path(__file__).resolve().parents[2] / "scripts" / "build" / "sync_vocabularies.py"
_SPEC = importlib.util.spec_from_file_location("sync_vocabularies", _MODULE)
assert _SPEC and _SPEC.loader
_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MOD
_SPEC.loader.exec_module(_MOD)

SyncPaths = _MOD.SyncPaths
sync_vocabularies = _MOD.sync_vocabularies
vocabulary_digest = _MOD.vocabulary_digest
list_vocab_files = _MOD.list_vocab_files
make_lock_payload = _MOD.make_lock_payload


def _write_vocab(path: Path, version: str) -> None:
    path.write_text(f'name = "demo"\nversion = "{version}"\n', encoding="utf-8")


def test_check_detects_drift_against_source(tmp_path: Path) -> None:
    source_dir = tmp_path / "specifications" / "vocabularies"
    target_dir = tmp_path / "bundle"
    source_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    _write_vocab(source_dir / "example.vocab.toml", "1.0")
    _write_vocab(target_dir / "example.vocab.toml", "0.9")

    paths = SyncPaths(
        source_vocabulary_dir=source_dir,
        target_vocabulary_dir=target_dir,
        lockfile_path=tmp_path / "data" / "specifications.lock.json",
        specifications_root=tmp_path / "specifications",
    )
    result = sync_vocabularies(paths=paths, check=True, specifications_sha="abc123")
    assert result == 1


def test_sync_updates_bundle_and_lockfile(tmp_path: Path) -> None:
    source_dir = tmp_path / "specifications" / "vocabularies"
    target_dir = tmp_path / "bundle"
    source_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    _write_vocab(source_dir / "alpha.vocab.toml", "1.0")
    _write_vocab(source_dir / "beta.vocab.toml", "2.0")
    _write_vocab(target_dir / "alpha.vocab.toml", "0.9")
    _write_vocab(target_dir / "extra.vocab.toml", "9.9")

    lockfile = tmp_path / "data" / "specifications.lock.json"
    paths = SyncPaths(
        source_vocabulary_dir=source_dir,
        target_vocabulary_dir=target_dir,
        lockfile_path=lockfile,
        specifications_root=tmp_path / "specifications",
    )
    result = sync_vocabularies(paths=paths, check=False, specifications_sha="deadbeef")
    assert result == 0
    assert not (target_dir / "extra.vocab.toml").exists()
    alpha_text = (target_dir / "alpha.vocab.toml").read_text(encoding="utf-8")
    assert alpha_text.endswith('version = "1.0"\n')
    assert (target_dir / "beta.vocab.toml").exists()

    lock = json.loads(lockfile.read_text(encoding="utf-8"))
    expected = make_lock_payload(
        specifications_sha="deadbeef",
        bundled_digest=vocabulary_digest(list_vocab_files(source_dir)),
        managed_files=["alpha.vocab.toml", "beta.vocab.toml"],
    )
    assert lock == expected


def test_check_without_source_uses_bundled_baseline(tmp_path: Path) -> None:
    source_dir = tmp_path / "missing-specifications" / "vocabularies"
    target_dir = tmp_path / "bundle"
    target_dir.mkdir(parents=True)
    _write_vocab(target_dir / "example.vocab.toml", "1.0")

    digest = vocabulary_digest(list_vocab_files(target_dir))
    lockfile = tmp_path / "data" / "specifications.lock.json"
    lockfile.parent.mkdir(parents=True)
    lockfile.write_text(
        json.dumps(
            make_lock_payload(
                specifications_sha="baseline-bundled-state",
                bundled_digest=digest,
                managed_files=["example.vocab.toml"],
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    paths = SyncPaths(
        source_vocabulary_dir=source_dir,
        target_vocabulary_dir=target_dir,
        lockfile_path=lockfile,
        specifications_root=tmp_path / "missing-specifications",
    )
    assert sync_vocabularies(paths=paths, check=True) == 0

    _write_vocab(target_dir / "example.vocab.toml", "2.0")
    assert sync_vocabularies(paths=paths, check=True) == 1
