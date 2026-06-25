"""Read and write ``{field}.vocab.toml`` vocabulary documents."""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from opentide.core.io import load_toml
from opentide.generation.vocabulary import (
    VocabularyDefinition,
    VocabularyLoadError,
    parse_vocabulary_document,
)

VocabKey = Literal["name", "id"]
VOCAB_SUFFIX = ".vocab.toml"

# Sequential internal ids (IMP0001, SEV0001) that are not canonical external identifiers.
_SEQUENTIAL_ID = re.compile(r"^[A-Z]{2,5}\d{4}$")


def field_from_vocab_path(path: Path) -> str:
    """Return vocabulary field name from a ``{field}.vocab.toml`` path."""
    name = path.name
    if not name.endswith(VOCAB_SUFFIX):
        raise VocabularyLoadError(f"Not a vocabulary file: {path}")
    return name[: -len(VOCAB_SUFFIX)]


def validate_field_matches_path(raw: Mapping[str, Any], path: Path) -> None:
    """Assert in-file ``field`` matches the filename stem."""
    expected = field_from_vocab_path(path)
    actual = raw.get("field")
    if actual != expected:
        raise VocabularyLoadError(
            f"Vocabulary field '{actual}' does not match filename '{expected}' in {path.name}"
        )


def strip_spurious_entry_id(
    entry: Mapping[str, Any],
    *,
    vocab_key: VocabKey,
    field: str,
) -> dict[str, Any]:
    """Remove meaningless ``id`` values from name-keyed vocabulary entries."""
    if vocab_key == "id":
        return dict(entry)
    entry_id = entry.get("id")
    if entry_id is None:
        return dict(entry)
    cleaned = dict(entry)
    if _SEQUENTIAL_ID.match(str(entry_id)):
        cleaned.pop("id", None)
        return cleaned
    if field == "surface":
        try:
            uuid.UUID(str(entry_id))
            cleaned.pop("id", None)
            return cleaned
        except ValueError:
            pass
    return cleaned


def read_vocab_document(path: Path) -> dict[str, Any]:
    """Load a vocabulary TOML file into a plain dict."""
    source = str(path)
    try:
        raw = load_toml(path)
    except Exception as exc:
        raise VocabularyLoadError(f"Could not read vocabulary TOML {source}: {exc}") from exc
    if not raw:
        raise VocabularyLoadError(f"Empty vocabulary TOML file: {source}")
    if not isinstance(raw, dict):
        raise VocabularyLoadError(f"Vocabulary TOML must be a table: {source}")
    validate_field_matches_path(raw, path)
    return raw


def load_vocab_file(path: Path) -> VocabularyDefinition:
    """Load and parse a ``{field}.vocab.toml`` file."""
    raw = read_vocab_document(path)
    return parse_vocabulary_document(raw, source=path.name)


def write_vocab_file(path: Path, document: Mapping[str, Any]) -> None:
    """Write a vocabulary document to TOML."""
    from opentide.vocabulary.writers import dump_vocab_document

    field = document.get("field")
    if field is None:
        raise VocabularyLoadError(f"Cannot write vocabulary without field: {path}")
    expected = field_from_vocab_path(path) if path.name.endswith(VOCAB_SUFFIX) else str(field)
    if field != expected:
        raise VocabularyLoadError(f"Vocabulary field '{field}' does not match path '{path.name}'")
    path.write_text(dump_vocab_document(document), encoding="utf-8")
