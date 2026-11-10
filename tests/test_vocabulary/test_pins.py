"""Which vocabulary fields the schema pin manifests reference."""

from __future__ import annotations

from pathlib import Path

from opentide._models.vocab_pins import pin_data_dir
from opentide.vocabulary.pins import (
    vocab_fields_in_pin_contents,
    vocab_fields_in_pin_dir,
    vocab_fields_in_pin_directories,
)


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
    from opentide._models.vocab_pins import get_pins

    threat = get_pins("threat::1.0")
    objective = get_pins("objective::1.0")
    assert threat["threat.mitre_attack"] == "att&ck::1.2"
    assert objective["objective.mitre_attack"] == "att&ck::1.2"
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


def test_bundled_pins_cover_every_shipped_schema() -> None:
    """Each registered revision has a pin table.

    The reverse does not hold: pins mirror specifications, which may pin a revision
    (``objective::1.1``) before opentide ships it. ``get_pins`` only reads the table of
    the schema being generated, so such a table is unused until then.
    """
    from opentide._models.schema_registry import identifiers_for_families
    from opentide._models.vocab_pins import pins_for_family

    families = ("threat", "objective", "rule")
    pinned = {schema_id for family in families for schema_id in pins_for_family(family)}
    assert set(identifiers_for_families(families)) <= pinned


def test_bundled_pins_resolve_against_bundled_vocabularies() -> None:
    from opentide._models.vocab_pins import pins_for_family
    from opentide.generation.vocabulary import VocabularyRevisionResolver, parse_vocab_contract
    from opentide.package.paths import bundled_data_root
    from opentide.vocabulary.io import load_vocab_file

    vocab_dir = bundled_data_root() / "vocabulary"
    unresolved: list[str] = []
    for family in ("threat", "objective", "rule"):
        for schema_id, pins in pins_for_family(family).items():
            for dot_path, contract in pins.items():
                field, _version = parse_vocab_contract(contract)
                path = vocab_dir / f"{field}.vocab.toml"
                if not path.is_file():
                    unresolved.append(f"[{schema_id}] {dot_path}: no {path.name}")
                    continue
                if not VocabularyRevisionResolver.filter_entries(load_vocab_file(path), contract):
                    unresolved.append(f"[{schema_id}] {dot_path}: {contract} selects no keys")
    assert unresolved == []
