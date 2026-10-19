"""Tests for vocabulary sync/check maintainer script."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

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
list_pin_files = _MOD.list_pin_files
pin_tables_digest = _MOD.pin_tables_digest


def _write_vocab(path: Path, version: str) -> None:
    path.write_text(f'name = "demo"\nversion = "{version}"\n', encoding="utf-8")


def _write_pins(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _sync_paths(tmp_path: Path, specifications: str = "specifications") -> SyncPaths:
    return SyncPaths(
        source_vocabulary_dir=tmp_path / specifications / "vocabularies",
        target_vocabulary_dir=tmp_path / "bundle",
        source_pins_dir=tmp_path / specifications / "schemas" / "pins",
        target_pins_dir=tmp_path / "pins",
        lockfile_path=tmp_path / "data" / "specifications.lock.json",
        specifications_root=tmp_path / specifications,
    )


_THREAT_PINS = (
    '["threat::1.0"]\n"threat.killchain" = "killchain::1.0"\n"metadata.tlp" = "tlp::1.0"\n'
)


def test_check_detects_drift_against_source(tmp_path: Path) -> None:
    paths = _sync_paths(tmp_path)
    source_dir = paths.source_vocabulary_dir
    target_dir = paths.target_vocabulary_dir
    source_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    _write_pins(paths.source_pins_dir / "threat.toml", _THREAT_PINS)
    _write_pins(paths.target_pins_dir / "threat.toml", _THREAT_PINS)
    _write_vocab(source_dir / "example.vocab.toml", "1.0")
    _write_vocab(target_dir / "example.vocab.toml", "0.9")

    result = sync_vocabularies(paths=paths, check=True, specifications_sha="abc123")
    assert result == 1


def test_sync_updates_bundle_and_lockfile(tmp_path: Path) -> None:
    paths = _sync_paths(tmp_path)
    source_dir = paths.source_vocabulary_dir
    target_dir = paths.target_vocabulary_dir
    source_dir.mkdir(parents=True)
    target_dir.mkdir(parents=True)
    _write_vocab(source_dir / "alpha.vocab.toml", "1.0")
    _write_vocab(source_dir / "beta.vocab.toml", "2.0")
    _write_vocab(target_dir / "alpha.vocab.toml", "0.9")
    _write_vocab(target_dir / "extra.vocab.toml", "9.9")
    _write_pins(paths.source_pins_dir / "threat.toml", _THREAT_PINS)
    _write_pins(paths.target_pins_dir / "extra.toml", '["extra::1.0"]\n')

    lockfile = paths.lockfile_path
    result = sync_vocabularies(paths=paths, check=False, specifications_sha="deadbeef")
    assert result == 0
    assert not (target_dir / "extra.vocab.toml").exists()
    alpha_text = (target_dir / "alpha.vocab.toml").read_text(encoding="utf-8")
    assert alpha_text.endswith('version = "1.0"\n')
    assert (target_dir / "beta.vocab.toml").exists()
    assert (paths.target_pins_dir / "threat.toml").read_text(encoding="utf-8") == _THREAT_PINS
    assert not (paths.target_pins_dir / "extra.toml").exists()

    lock = json.loads(lockfile.read_text(encoding="utf-8"))
    expected = make_lock_payload(
        specifications_sha="deadbeef",
        bundled_digest=vocabulary_digest(list_vocab_files(source_dir)),
        managed_files=["alpha.vocab.toml", "beta.vocab.toml"],
        pins_digest=pin_tables_digest(list_pin_files(paths.source_pins_dir)),
        managed_pin_files=["threat.toml"],
    )
    assert lock == expected
    assert sync_vocabularies(paths=paths, check=True, specifications_sha="deadbeef") == 0


def test_check_without_source_uses_bundled_baseline(tmp_path: Path) -> None:
    paths = _sync_paths(tmp_path, "missing-specifications")
    target_dir = paths.target_vocabulary_dir
    target_dir.mkdir(parents=True)
    _write_vocab(target_dir / "example.vocab.toml", "1.0")
    _write_pins(paths.target_pins_dir / "threat.toml", _THREAT_PINS)

    digest = vocabulary_digest(list_vocab_files(target_dir))
    lockfile = paths.lockfile_path
    lockfile.parent.mkdir(parents=True)
    lockfile.write_text(
        json.dumps(
            make_lock_payload(
                specifications_sha="baseline-bundled-state",
                bundled_digest=digest,
                managed_files=["example.vocab.toml"],
                pins_digest=pin_tables_digest(list_pin_files(paths.target_pins_dir)),
                managed_pin_files=["threat.toml"],
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    assert sync_vocabularies(paths=paths, check=True) == 0

    _write_vocab(target_dir / "example.vocab.toml", "2.0")
    assert sync_vocabularies(paths=paths, check=True) == 1


def test_check_without_source_detects_bundled_pin_edit(tmp_path: Path) -> None:
    paths = _sync_paths(tmp_path, "missing-specifications")
    paths.target_vocabulary_dir.mkdir(parents=True)
    _write_vocab(paths.target_vocabulary_dir / "example.vocab.toml", "1.0")
    _write_pins(paths.target_pins_dir / "threat.toml", _THREAT_PINS)
    assert sync_vocabularies(paths=paths, check=False) == 0
    assert sync_vocabularies(paths=paths, check=True) == 0

    _write_pins(paths.target_pins_dir / "threat.toml", _THREAT_PINS + '\n["threat::2.1"]\n')
    assert sync_vocabularies(paths=paths, check=True) == 1


def test_check_without_source_accepts_lockfile_synced_from_specifications(
    tmp_path: Path,
) -> None:
    paths = _sync_paths(tmp_path)
    paths.source_vocabulary_dir.mkdir(parents=True)
    _write_vocab(paths.source_vocabulary_dir / "example.vocab.toml", "1.0")
    _write_pins(paths.source_pins_dir / "threat.toml", _THREAT_PINS)
    assert sync_vocabularies(paths=paths, check=False, specifications_sha="deadbeef") == 0

    # CI has no specifications checkout: the recorded SHA is provenance, not content.
    ci_paths = replace(
        paths,
        source_vocabulary_dir=tmp_path / "missing" / "vocabularies",
        source_pins_dir=tmp_path / "missing" / "schemas" / "pins",
        specifications_root=tmp_path / "missing",
    )
    assert sync_vocabularies(paths=ci_paths, check=True) == 0


def test_check_reports_pin_drift_against_source(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = _sync_paths(tmp_path)
    for directory in (paths.source_vocabulary_dir, paths.target_vocabulary_dir):
        directory.mkdir(parents=True)
        _write_vocab(directory / "example.vocab.toml", "1.0")
    _write_pins(paths.source_pins_dir / "threat.toml", _THREAT_PINS)
    _write_pins(
        paths.source_pins_dir / "rule.toml", '["rule::1.0"]\n"severity" = "severity::1.0"\n'
    )
    _write_pins(
        paths.target_pins_dir / "threat.toml",
        '["threat::1.0"]\n"threat.killchain" = "killchain::1.1"\n"threat.extra" = "extra::1.0"\n'
        '\n["threat::2.1"]\n"threat.killchain" = "killchain::1.1"\n',
    )

    assert sync_vocabularies(paths=paths, check=True, specifications_sha="abc123") == 1
    out = capsys.readouterr().out
    assert "Pin drift detected:" in out
    assert "rule.toml" in out
    assert "[threat::1.0] metadata.tlp: missing (specifications pins tlp::1.0)" in out
    assert "[threat::1.0] threat.extra: not in specifications (bundled pins extra::1.0)" in out
    assert (
        "[threat::1.0] threat.killchain: bundled killchain::1.1, specifications killchain::1.0"
        in out
    )
    assert "[threat::2.1] schema revision not in specifications" in out


def test_pin_comments_and_formatting_are_not_drift(tmp_path: Path) -> None:
    paths = _sync_paths(tmp_path)
    for directory in (paths.source_vocabulary_dir, paths.target_vocabulary_dir):
        directory.mkdir(parents=True)
        _write_vocab(directory / "example.vocab.toml", "1.0")
    _write_pins(paths.source_pins_dir / "threat.toml", _THREAT_PINS)
    bundled = (
        "# Bundled copy keeps its own notes.\n"
        '["threat::1.0"]\n'
        '"metadata.tlp" = "tlp::1.0"\n'
        '"threat.killchain"   =   "killchain::1.0"\n'
    )
    _write_pins(paths.target_pins_dir / "threat.toml", bundled)

    assert sync_vocabularies(paths=paths, check=False, specifications_sha="abc123") == 0
    assert (paths.target_pins_dir / "threat.toml").read_text(encoding="utf-8") == bundled
    assert sync_vocabularies(paths=paths, check=True, specifications_sha="abc123") == 0


def test_missing_source_pins_directory_fails_without_touching_bundle(tmp_path: Path) -> None:
    paths = _sync_paths(tmp_path)
    paths.source_vocabulary_dir.mkdir(parents=True)
    _write_vocab(paths.source_vocabulary_dir / "example.vocab.toml", "1.0")
    _write_pins(paths.target_pins_dir / "threat.toml", _THREAT_PINS)

    assert sync_vocabularies(paths=paths, check=False, specifications_sha="abc123") == 1
    assert (paths.target_pins_dir / "threat.toml").read_text(encoding="utf-8") == _THREAT_PINS
    assert not paths.lockfile_path.exists()
