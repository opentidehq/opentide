"""Bundled pins must resolve against the bundled vocabularies (#568).

0.13.0 (#504) re-synced ``att&ck`` from a copy that had no key at ``1.1``
while every schema pinned ``att&ck::1.1``. Validation kept working, against
ATT&CK v17, and techniques added since were rejected. These tests fail on
that state.
"""

from __future__ import annotations

from functools import cache

import pytest

from opentide.generation.vocabulary import (
    VocabularyDefinition,
    VocabularyLoader,
    VocabularyRevisionResolver,
    parse_vocab_contract,
)
from opentide.models.schema_registry import is_registered
from opentide.models.vocab_pins import get_pins, pin_data_dir, pins_for_family

_VOCABULARY_DIR = pin_data_dir().parent / "vocabulary"


@cache
def _bundled(field: str) -> VocabularyDefinition:
    return VocabularyLoader.load_from_vocab_file(_VOCABULARY_DIR / f"{field}.vocab.toml")


def _bundled_pins() -> list[tuple[str, str, str]]:
    """Pins of every shipped schema revision.

    Sections for revisions with no registered model (``threat::2.1``) are not
    used to validate anything, so they are left to the pin-drift check.
    """
    return [
        (schema_id, path, contract)
        for family in ("threat", "objective", "rule")
        for schema_id, pins in pins_for_family(family).items()
        if is_registered(schema_id)
        for path, contract in pins.items()
    ]


def test_shipped_revisions_have_pins() -> None:
    schema_ids = {schema_id for schema_id, _path, _contract in _bundled_pins()}

    assert {"threat::1.0", "objective::1.0", "rule::1.0", "rule::1.1"} <= schema_ids


@pytest.mark.parametrize(
    ("schema_id", "path", "contract"),
    _bundled_pins(),
    ids=lambda value: str(value),
)
def test_every_pinned_minor_is_introduced_by_a_bundled_key(
    schema_id: str, path: str, contract: str
) -> None:
    """A pin naming ``field::M.m`` needs at least one key at version ``M.m``."""
    field, version = parse_vocab_contract(contract)
    assert (_VOCABULARY_DIR / f"{field}.vocab.toml").is_file(), (
        f"{schema_id} {path} pins {contract} but {field}.vocab.toml is not bundled"
    )
    versions = {entry.version for entry in _bundled(field).entries.values()}
    assert version in versions, (
        f"{schema_id} {path} pins {contract} but no bundled {field} key is at {version}"
    )


@pytest.mark.parametrize(
    "technique",
    [
        "T1059.013",  # ATT&CK v18
        "T1685",  # ATT&CK v19 Defense Impairment
        "T1685.002",
        "T1696",  # ATT&CK v20
        "T1562.001",  # revoked in v19; removed only at att&ck::2.0
    ],
)
@pytest.mark.parametrize(
    ("schema_id", "path"),
    [
        ("rule::1.0", "techniques"),
        ("rule::1.1", "techniques"),
        ("threat::1.0", "threat.mitre_attack"),
        ("objective::1.0", "objective.mitre_attack"),
    ],
)
def test_pinned_attack_contract_accepts_current_techniques(
    schema_id: str, path: str, technique: str
) -> None:
    contract = get_pins(schema_id)[path]
    field, _version = parse_vocab_contract(contract)
    assert field == "att&ck"

    active = VocabularyRevisionResolver.filter_entries(_bundled(field), contract)

    assert technique in active


def test_bundled_attack_records_its_source_release() -> None:
    """Every ATT&CK ingest stamps its release; the v17 copy (#504) had none."""
    metadata = _bundled("att&ck").metadata

    assert metadata.get("source") == "mitre-attack"
    assert metadata.get("source_version")
