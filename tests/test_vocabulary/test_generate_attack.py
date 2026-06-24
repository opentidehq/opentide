"""ATT&CK vocabulary generation from STIX bundles."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentide.vocabulary import generate_attack


def test_generate_attack_vocabs_writes_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stix_dir = tmp_path / "attack" / "stix"
    vocab_dir = tmp_path / "vocabs"
    stix_dir.mkdir(parents=True)
    vocab_dir.mkdir()
    bundle = {"type": "bundle", "objects": []}
    (stix_dir / "enterprise-attack.json").write_text(json.dumps(bundle), encoding="utf-8")
    (stix_dir / "manifest.json").write_text(
        json.dumps({"version": "14.0", "fetched_at": "2026-01-01T00:00:00Z"}),
        encoding="utf-8",
    )
    for field in ("att&ck", "att&ck.groups", "mitigations", "datasources"):
        (vocab_dir / f"{field}.vocab.toml").write_text(
            f'name = "{field}"\nfield = "{field}"\nkeys = []\n',
            encoding="utf-8",
        )

    monkeypatch.setattr(generate_attack, "_resources_root", lambda: tmp_path)
    monkeypatch.setattr(generate_attack, "_vocab_dir", lambda: vocab_dir)
    monkeypatch.setattr(generate_attack, "_stix_dir", lambda: stix_dir)
    monkeypatch.setattr(generate_attack, "merge_technique_bundles", lambda _b: [])
    monkeypatch.setattr(generate_attack, "parse_groups", lambda _b, prefix="": [])
    monkeypatch.setattr(generate_attack, "parse_mitigations", lambda _b, prefix="": [])
    monkeypatch.setattr(generate_attack, "parse_datasources", lambda _b: [])
    monkeypatch.setattr(generate_attack, "load_stix_bundle", lambda _p: bundle)
    monkeypatch.setattr(generate_attack, "write_vocab_file", lambda _p, _d: None)

    counts = generate_attack.generate_attack_vocabs()
    assert set(counts) == {"att&ck", "att&ck.groups", "mitigations", "datasources"}


def test_generate_attack_vocabs_missing_bundle_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stix_dir = tmp_path / "attack" / "stix"
    stix_dir.mkdir(parents=True)
    monkeypatch.setattr(generate_attack, "_stix_dir", lambda: stix_dir)
    with pytest.raises(FileNotFoundError, match="STIX bundle not found"):
        generate_attack.generate_attack_vocabs()
