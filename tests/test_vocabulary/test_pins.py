"""Schema pin bumping for vocabulary ingest."""

from __future__ import annotations

from pathlib import Path

from opentide.models.vocab_pins import pin_data_dir
from opentide.vocabulary.pins import (
    bump_pin_contents,
    bump_pin_dir,
    bump_pin_file,
    should_bump,
    vocab_fields_in_pin_contents,
    vocab_fields_in_pin_dir,
    vocab_fields_in_pin_directories,
)


def test_should_bump_same_major_higher_minor() -> None:
    assert should_bump("1.0", "1.1")
    assert not should_bump("1.1", "1.1")
    assert not should_bump("1.1", "1.0")
    assert not should_bump("1.1", "2.0")


def test_bump_pin_contents_updates_matching_contracts() -> None:
    text = (
        '["threat::1.0"]\n'
        '"threat.att&ck" = "att&ck::1.0"\n'
        '"threat.actors" = "actors::1.0"\n'
        '"threat.killchain" = "killchain::1.1"\n'
        '"techniques" = "att&ck::1.0"\n'
    )
    rewritten, changes = bump_pin_contents(text, {"att&ck": "1.1", "actors": "1.1"})
    assert '"threat.att&ck" = "att&ck::1.1"' in rewritten
    assert '"threat.actors" = "actors::1.1"' in rewritten
    assert '"threat.killchain" = "killchain::1.1"' in rewritten
    assert '"techniques" = "att&ck::1.1"' in rewritten
    assert ("att&ck", "1.0", "1.1") in changes
    assert ("actors", "1.0", "1.1") in changes


def test_bump_pin_contents_never_advances_major() -> None:
    text = '"techniques" = "att&ck::1.0"\n'
    rewritten, changes = bump_pin_contents(text, {"att&ck": "2.0"})
    assert rewritten == text
    assert changes == []


def test_bump_pin_dir_rewrites_family_files(tmp_path: Path) -> None:
    threat = tmp_path / "threat.toml"
    objective = tmp_path / "objective.toml"
    threat.write_text('"threat.att&ck" = "att&ck::1.0"\n', encoding="utf-8")
    objective.write_text('"objective.attack" = "att&ck::1.0"\n', encoding="utf-8")
    (tmp_path / "rule.toml").write_text('"severity" = "severity::1.0"\n', encoding="utf-8")

    changes = bump_pin_dir(tmp_path, {"att&ck": "1.1"})
    assert len(changes) == 2
    assert "att&ck::1.1" in threat.read_text(encoding="utf-8")
    assert "att&ck::1.1" in objective.read_text(encoding="utf-8")


def test_bump_pin_file_missing_or_empty_versions(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    assert bump_pin_file(missing, {"att&ck": "1.1"}) == []
    present = tmp_path / "threat.toml"
    present.write_text('"threat.att&ck" = "att&ck::1.0"\n', encoding="utf-8")
    assert bump_pin_file(present, {}) == []
    assert present.read_text(encoding="utf-8") == '"threat.att&ck" = "att&ck::1.0"\n'


def test_vocab_fields_in_pin_contents_reads_contract_values() -> None:
    text = (
        '["threat::1.0"]\n'
        '"threat.att&ck" = "att&ck::1.0"\n'
        '"threat.actors" = "actors::1.0"\n'
        "# comment\n"
        '"threat.groups" = "not-a-pin"\n'
    )
    assert vocab_fields_in_pin_contents(text) == frozenset({"att&ck", "actors"})


def test_vocab_fields_in_pin_dir_skips_missing(tmp_path: Path) -> None:
    assert vocab_fields_in_pin_dir(tmp_path / "missing") == frozenset()
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    (pin_dir / "threat.toml").write_text('"threat.att&ck" = "att&ck::1.0"\n', encoding="utf-8")
    (pin_dir / "notes.toml").write_text('"ignored" = "mitigations::1.0"\n', encoding="utf-8")
    assert vocab_fields_in_pin_dir(pin_dir) == frozenset({"att&ck"})
    assert vocab_fields_in_pin_directories([pin_dir, tmp_path / "nope"]) == frozenset({"att&ck"})


def test_bundled_object_pins_use_mitre_attack_and_alert_severity() -> None:
    from opentide.models.vocab_pins import get_pins

    threat = get_pins("threat::1.0")
    objective = get_pins("objective::1.0")
    assert threat["threat.mitre_attack"] == "att&ck::1.1"
    assert objective["objective.mitre_attack"] == "att&ck::1.1"
    assert objective["objective.signals.severity"] == "alert_severity::1.0"
    assert "objective.signals.data.logsources" not in objective
    assert "threat.att&ck" not in threat
    assert "objective.attack" not in objective


def test_bundled_pins_do_not_reference_catalog_only_vocabs() -> None:
    fields = vocab_fields_in_pin_dir(pin_data_dir())
    assert {"att&ck", "actors", "alert_severity"} <= fields
    assert "datasources" not in fields
    assert "att&ck.groups" not in fields
    assert "mitigations" not in fields


def test_bundled_pins_only_cover_shipped_schemas() -> None:
    from opentide.models.schema_registry import registered_identifiers
    from opentide.models.vocab_pins import pins_for_family

    pinned = {
        schema_id
        for family in ("threat", "objective", "rule")
        for schema_id in pins_for_family(family)
    }
    assert pinned <= set(registered_identifiers())


def test_bundled_pins_resolve_against_bundled_vocabularies() -> None:
    from opentide.generation.vocabulary import VocabularyRevisionResolver, parse_vocab_contract
    from opentide.models.vocab_pins import pins_for_family
    from opentide.package.paths import bundled_data_root
    from opentide.vocabulary.io import load_vocab_file

    vocab_dir = bundled_data_root() / "vocabulary"
    unresolved: list[str] = []
    for family in ("threat", "objective", "rule"):
        for schema_id, pins in pins_for_family(family).items():
            for dot_path, contract in pins.items():
                field, version = parse_vocab_contract(contract)
                path = vocab_dir / f"{field}.vocab.toml"
                if not path.is_file():
                    unresolved.append(f"[{schema_id}] {dot_path}: no {path.name}")
                    continue
                if not VocabularyRevisionResolver.filter_entries(load_vocab_file(path), contract):
                    unresolved.append(f"[{schema_id}] {dot_path}: {contract} selects no keys")
    assert unresolved == []
