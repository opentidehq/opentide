"""Tests for vocabulary writers."""

from __future__ import annotations

from opentide.vocabulary.writers import dump_vocab_document


def test_dump_vocab_document_roundtrip_shape() -> None:
    document = {
        "name": "Severity",
        "field": "severity",
        "key": "name",
        "entries": [{"name": "High"}],
    }
    rendered = dump_vocab_document(document)
    assert 'field = "severity"' in rendered
    assert "[[entries]]" in rendered


def test_dump_vocab_document_serializes_list_fields_in_aot() -> None:
    document = {
        "name": "Actors",
        "field": "actors",
        "key": "name",
        "keys": [{"name": "APT1", "alias": ["Comment Crew", "CommentGroup"]}],
    }
    rendered = dump_vocab_document(document)
    assert "[[keys]]" in rendered
    assert "alias" in rendered
