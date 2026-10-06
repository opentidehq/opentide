"""Tests for cross-object validation checks."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from opentide.validation.checks.cross_object import (
    check_chaining_for_object,
    check_references_for_object,
)


def test_check_references_invalid_detection_model() -> None:
    graph = MagicMock()
    graph.resolve.return_value = MagicMock(file_path=Path("rule.yaml"))
    graph.enum_values.return_value = frozenset({"obj-1"})
    graph.format_invalid_ref.return_value = "bad ref"
    graph.suggest_ref.return_value = None

    issues = check_references_for_object(
        "rule-1",
        "rule",
        {"detection_model": "missing-objective-uuid"},
        graph,
    )
    assert len(issues) == 1
    assert issues[0].code == "invalid_ref"


def test_signal_and_objective_uuids_are_valid_detection_models() -> None:
    graph = MagicMock()
    graph.resolve.return_value = MagicMock(file_path=Path("rule.yaml"))

    def values(kind: str) -> frozenset[str]:
        if kind == "signal":
            return frozenset({"sig-1"})
        if kind == "objective":
            return frozenset({"obj-1"})
        return frozenset()

    graph.enum_values.side_effect = values
    assert check_references_for_object("rule-1", "rule", {"detection_model": "sig-1"}, graph) == []
    assert check_references_for_object("rule-1", "rule", {"detection_model": "obj-1"}, graph) == []


def test_check_references_unknown_type_returns_empty() -> None:
    graph = MagicMock()
    assert check_references_for_object("x", "unknown", {}, graph) == []


def test_check_references_invalid_objective_threat() -> None:
    graph = MagicMock()
    graph.resolve.return_value = MagicMock(file_path=Path("obj.yaml"))
    graph.enum_values.return_value = frozenset({"thr-1"})
    graph.format_invalid_ref.return_value = "bad threat"
    graph.suggest_ref.return_value = None

    issues = check_references_for_object(
        "obj-1",
        "objective",
        {"objective": {"threats": ["missing-threat"]}},
        graph,
    )
    assert len(issues) == 1
    assert issues[0].field_path == ("objective", "threats")


def test_check_chaining_for_threat_invalid_relation() -> None:
    graph = MagicMock()
    graph.resolve.return_value = MagicMock(file_path=Path("t.yaml"))
    graph.enum_resolver.enum_values.return_value = frozenset({"precedes"})
    graph.enum_resolver.is_valid.return_value = False
    graph.enum_resolver.suggest.return_value = "precedes"
    issues = check_chaining_for_object(
        "thr-1",
        {"threat": {"chaining": [{"relation": "invalid-rel"}]}},
        graph,
    )
    assert len(issues) == 1
    assert issues[0].code == "chaining_relation_unknown"
