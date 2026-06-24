"""Field vocabulary walk tests with mocked graph."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.validation.field_vocab import walk_vocab_fields


def test_walk_vocab_fields_validates_enum_value() -> None:
    graph = MagicMock()
    graph.enum_resolver.is_valid.return_value = False
    graph.enum_resolver.suggest.return_value = "High"
    schema = {"properties": {"severity": {"tide.vocab": "severity"}}}
    payload = {"severity": "Invalid"}
    issues = walk_vocab_fields(payload, schema, graph, object_uuid="u1", object_type="rule")
    assert len(issues) == 1
    assert issues[0].code == "vocab_unknown"
