"""Bulk cross-object validation coverage."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.validation.checks.cross_object import check_chaining, check_references


def test_check_references_bulk() -> None:
    graph = MagicMock()
    graph.resolve.return_value = None
    graph.enum_values.return_value = frozenset()
    graph.format_invalid_ref.return_value = "bad"
    graph.suggest_ref.return_value = None
    index = {
        "rule": {"r1": {"detection_model": "missing"}},
        "objective": {},
        "threat": {},
    }
    issues = check_references(index, graph)
    assert len(issues) == 1


def test_check_chaining_bulk() -> None:
    graph = MagicMock()
    graph.resolve.return_value = None
    graph.enum_resolver.enum_values.return_value = frozenset()
    graph.enum_resolver.is_valid.return_value = True
    index = {
        "threat": {
            "t1": {"threat": {"chaining": [{"relation": "precedes"}]}},
        }
    }
    issues = check_chaining(index, graph)
    assert issues == []
