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


def test_strip_spurious_entry_id_keeps_external_id_for_id_keyed_vocab() -> None:
    cleaned = io.strip_spurious_entry_id(
        {"id": "G0001", "name": "APT1"},
        vocab_key="id",
        field="actors",
    )
    assert cleaned["id"] == "G0001"


def test_strip_spurious_entry_id_without_id_returns_copy() -> None:
    cleaned = io.strip_spurious_entry_id(
        {"name": "High"},
        vocab_key="name",
        field="severity",
    )
    assert cleaned == {"name": "High"}


def test_strip_spurious_entry_id_keeps_non_sequential_id() -> None:
    cleaned = io.strip_spurious_entry_id(
        {"name": "High", "id": "custom-id"},
        vocab_key="name",
        field="severity",
    )
    assert cleaned["id"] == "custom-id"


def test_strip_spurious_entry_id_keeps_uuid_for_non_surface_field() -> None:
    cleaned = io.strip_spurious_entry_id(
        {"name": "Item", "id": "00000000-0000-4000-8000-000000000099"},
        vocab_key="name",
        field="severity",
    )
    assert cleaned["id"] == "00000000-0000-4000-8000-000000000099"


def test_read_vocab_document_rejects_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.vocab.toml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(VocabularyLoadError, match="Empty vocabulary"):
        io.read_vocab_document(path)


def test_read_vocab_document_rejects_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "broken.vocab.toml"
    path.write_text("field = severity\n[[[", encoding="utf-8")
    with pytest.raises(VocabularyLoadError, match="Could not read vocabulary TOML"):
        io.read_vocab_document(path)


def test_read_vocab_document_rejects_non_mapping_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "severity.vocab.toml"
    path.write_text('field = "severity"\n', encoding="utf-8")
    monkeypatch.setattr("opentide.vocabulary.io.load_toml", lambda _path: ["not-a-table"])
    with pytest.raises(VocabularyLoadError, match="must be a table"):
        io.read_vocab_document(path)


def test_write_vocab_file_rejects_field_path_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "severity.vocab.toml"
    with pytest.raises(VocabularyLoadError, match="does not match path"):
        io.write_vocab_file(path, {"field": "other", "name": "Severity", "keys": []})
