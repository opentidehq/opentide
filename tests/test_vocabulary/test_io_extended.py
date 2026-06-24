"""Extended vocabulary I/O coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.generation.vocabulary import VocabularyLoadError
from opentide.vocabulary import io


def test_write_vocab_file_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "severity.vocab.toml"
    document = {
        "name": "Severity",
        "field": "severity",
        "key": "name",
        "entries": [{"name": "High"}],
    }
    io.write_vocab_file(path, document)
    loaded = io.read_vocab_document(path)
    assert loaded["field"] == "severity"


def test_write_vocab_file_requires_field(tmp_path: Path) -> None:
    path = tmp_path / "bad.vocab.toml"
    with pytest.raises(VocabularyLoadError):
        io.write_vocab_file(path, {"name": "Bad"})


def test_validate_field_matches_path_mismatch(tmp_path: Path) -> None:
    with pytest.raises(VocabularyLoadError):
        io.validate_field_matches_path({"field": "other"}, tmp_path / "severity.vocab.toml")


def test_strip_spurious_entry_id_keeps_uuid_for_surface() -> None:
    cleaned = io.strip_spurious_entry_id(
        {"name": "Endpoint", "id": "00000000-0000-4000-8000-000000000099"},
        vocab_key="name",
        field="surface",
    )
    assert "id" not in cleaned
