"""Vocabulary I/O, STIX extraction, and TOML generation."""

from opentide.generation.vocabulary import resolve_vocab_key
from opentide.vocabulary.io import (
    field_from_vocab_path,
    load_vocab_file,
    read_vocab_document,
    strip_spurious_entry_id,
    validate_field_matches_path,
    write_vocab_file,
)

__all__ = [
    "field_from_vocab_path",
    "load_vocab_file",
    "read_vocab_document",
    "resolve_vocab_key",
    "strip_spurious_entry_id",
    "validate_field_matches_path",
    "write_vocab_file",
]
