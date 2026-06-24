"""Tests for metaschema-driven vocabulary field validation."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.validation.field_vocab import (
    validate_object_vocab_from_metaschema,
    walk_vocab_fields,
)
from opentide.validation.issues import ValidationIssue


def _mock_graph(*, valid: bool = True, suggestion: str | None = None) -> MagicMock:
    graph = MagicMock()
    graph.enum_resolver.is_valid.return_value = valid
    graph.enum_resolver.suggest.return_value = suggestion
    return graph


def test_walk_vocab_fields_valid_value() -> None:
    graph = _mock_graph(valid=True)
    schema = {"properties": {"severity": {"tide.vocab": "severity"}}}
    payload = {"severity": "High"}
    issues = walk_vocab_fields(payload, schema, graph, object_uuid="u1", object_type="rule")
    assert issues == []
    graph.enum_resolver.is_valid.assert_called_once()


def test_walk_vocab_fields_unknown_value() -> None:
    graph = _mock_graph(valid=False, suggestion="High")
    schema = {"properties": {"severity": {"tide.vocab": "severity"}}}
    payload = {"severity": "Hgh"}
    issues = walk_vocab_fields(payload, schema, graph, object_uuid="u1", object_type="rule")
    assert len(issues) == 1
    assert issues[0].code == "vocab_unknown"
    assert issues[0].suggestion == "High"


def test_walk_vocab_fields_array_items() -> None:
    graph = _mock_graph(valid=False, suggestion="T1059")
    schema = {
        "properties": {
            "techniques": {
                "type": "array",
                "items": {"tide.vocab": "technique"},
            }
        }
    }
    payload = {"techniques": ["T9999"]}
    issues = walk_vocab_fields(payload, schema, graph)
    assert len(issues) == 1
    assert issues[0].field_path == ("techniques", "0")


def test_validate_object_vocab_from_metaschema_missing_type() -> None:
    graph = _mock_graph()
    issues = validate_object_vocab_from_metaschema({}, {}, "unknown", graph)
    assert issues == []


def test_validate_object_vocab_from_metaschema_with_schema() -> None:
    graph = _mock_graph(valid=True)
    metaschemas = {"rule": {"properties": {"status": {"tide.vocab": "status"}}}}
    payload = {"status": "STAGING"}
    issues = validate_object_vocab_from_metaschema(
        payload, metaschemas, "rule", graph, object_uuid="abc"
    )
    assert isinstance(issues, list)
    assert all(isinstance(i, ValidationIssue) for i in issues)
