"""Metaschema-driven vocab validation entry."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.validation.field_vocab import validate_object_vocab_from_metaschema


def test_validate_object_vocab_from_metaschema_missing_schema() -> None:
    graph = MagicMock()
    assert validate_object_vocab_from_metaschema({}, {}, "rule", graph) == []


def test_validate_object_vocab_from_metaschema_with_schema() -> None:
    graph = MagicMock()
    graph.enum_resolver.is_valid.return_value = True
    metaschemas = {"rule": {"properties": {"severity": {"tide.vocab": "severity"}}}}
    payload = {"severity": "High"}
    issues = validate_object_vocab_from_metaschema(
        payload,
        metaschemas,
        "rule",
        graph,
        object_uuid="u1",
    )
    assert issues == []
