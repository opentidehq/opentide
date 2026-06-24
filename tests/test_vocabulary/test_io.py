"""Tests for vocabulary I/O helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.generation.vocabulary import VocabularyLoadError
from opentide.vocabulary import io


def test_field_from_vocab_path() -> None:
    assert io.field_from_vocab_path(Path("severity.vocab.toml")) == "severity"


def test_field_from_vocab_path_rejects_non_vocab() -> None:
    with pytest.raises(VocabularyLoadError):
        io.field_from_vocab_path(Path("severity.toml"))


def test_strip_spurious_entry_id_removes_sequential() -> None:
    cleaned = io.strip_spurious_entry_id(
        {"name": "High", "id": "SEV0001"},
        vocab_key="name",
        field="severity",
    )
    assert "id" not in cleaned


def test_read_vocab_document(tmp_path: Path) -> None:
    path = tmp_path / "severity.vocab.toml"
    path.write_text(
        'field = "severity"\nkey = "name"\n[[entries]]\nname = "High"\n',
        encoding="utf-8",
    )
    raw = io.read_vocab_document(path)
    assert raw["field"] == "severity"


def test_load_vocab_file(tmp_path: Path) -> None:
    path = tmp_path / "severity.vocab.toml"
    path.write_text(
        'name = "Severity"\nfield = "severity"\nkey = "name"\n[[entries]]\nname = "High"\n',
        encoding="utf-8",
    )
    definition = io.load_vocab_file(path)
    assert definition.metadata.field == "severity"
