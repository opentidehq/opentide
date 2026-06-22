"""Unit tests for EnumResolver bug fixes (Phase 3)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Engines.framework.json_schemas import EnumResolver  # noqa: E402
from Engines.modules.vocabulary import (  # noqa: E402
    VocabularyDefinition,
    VocabularyEntry,
    VocabularyMetadata,
)


@pytest.fixture
def impact_vocab() -> VocabularyDefinition:
    return VocabularyDefinition(
        metadata=VocabularyMetadata(
            name="Impact",
            field="impact",
            model=False,
            extra={"vocab.search_hints": True},
        ),
        entries={
            "Nuisance": VocabularyEntry(name="Nuisance", description="Small impact"),
            "Data Breach": VocabularyEntry(name="Data Breach", description="Breach"),
        },
    )


def test_finalise_does_not_duplicate_descriptions(impact_vocab: VocabularyDefinition) -> None:
    with patch("Engines.framework.json_schemas.VOCAB_INDEX", {"impact": impact_vocab}):
        resolver = EnumResolver.Vocabulary("impact", no_wrap=True)
        enum, descriptions = resolver.resolve()

    assert len(enum) == len(descriptions)
    assert len(descriptions) == len(set(descriptions)) or descriptions.count(descriptions[0]) == 1


def test_finalise_appends_hint_descriptions_for_model_vocab() -> None:
    model_vocab = VocabularyDefinition(
        metadata=VocabularyMetadata(
            name="Rules",
            field="mdr",
            model=True,
            extra={"vocab.search_hints": True},
        ),
        entries={
            "rule-1": VocabularyEntry(name="Rule One", description="First rule"),
        },
    )
    with patch("Engines.framework.json_schemas.VOCAB_INDEX", {"mdr": model_vocab}):
        with patch("Engines.framework.json_schemas.OBJECT_TYPES", ["mdr"]):
            resolver = EnumResolver.Vocabulary("mdr", no_wrap=True)
            enum, descriptions = resolver.resolve()

    assert len(enum) == len(descriptions)
    assert len(enum) == 2
    assert enum[0] == "rule-1"
    assert "Rule One" in enum[1]


def test_field_types_string_normalisation_uses_isinstance() -> None:
    source = (ROOT / "Engines/framework/json_schemas.py").read_text()
    assert "type(field_types) is str()" not in source
    assert "isinstance(field_types, str)" in source


def test_finalise_no_self_extend_bug() -> None:
    source = (ROOT / "Engines/framework/json_schemas.py").read_text()
    assert "enum_description.extend(self.enum_description)" not in source
    assert "_hint_descriptions" in source
