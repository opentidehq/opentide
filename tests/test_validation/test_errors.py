"""Tests for validation error transformation helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, Field, ValidationError

from opentide.models.threat import ThreatVector
from opentide.validation.errors import (
    attach_yaml_lines,
    format_issues_for_console,
    is_vocab_shape_duplicate,
    issues_from_pydantic,
    vocab_shape_rejections,
)
from opentide.validation.issues import ValidationIssue


class _SampleModel(BaseModel):
    name: str = Field(min_length=3)
    threat: str = ""


def test_issues_from_pydantic_basic() -> None:
    try:
        _SampleModel(name="x")
    except ValidationError as exc:
        issues = issues_from_pydantic(exc, object_uuid="obj-1", object_type="rule")
    assert len(issues) == 1
    assert issues[0].code == "schema_validation"
    assert issues[0].object_uuid == "obj-1"
    assert issues[0].field_path == ("name",)


class _RefModel(BaseModel):
    name: str = Field(min_length=3)
    threat: str = ""


def test_issues_from_pydantic_with_graph_suggestion() -> None:
    graph = MagicMock()
    graph.suggest_ref.return_value = "good-uuid"
    graph.enum_resolver.suggest.return_value = None
    exc = ValidationError.from_exception_data(
        "RefModel",
        [
            {
                "type": "string_too_short",
                "loc": ("objective", "threats", 0),
                "msg": "invalid threat ref",
                "input": "bad-ref",
                "ctx": {"min_length": 3},
            }
        ],
    )
    issues = issues_from_pydantic(
        exc,
        object_uuid="obj-1",
        object_type="rule",
        graph=graph,
    )
    assert issues
    assert issues[0].code == "invalid_ref"
    assert issues[0].suggestion == "good-uuid"


def test_issues_from_pydantic_nested_threat_body_is_not_invalid_ref() -> None:
    graph = MagicMock()
    graph.suggest_ref.return_value = "should-not-be-used"
    graph.enum_resolver.suggest.return_value = None
    exc = ValidationError.from_exception_data(
        "ThreatVector",
        [
            {
                "type": "string_type",
                "loc": ("threat", "actors"),
                "msg": "Input should be a valid dictionary",
                "input": "not-an-actor",
            }
        ],
    )
    issues = issues_from_pydantic(exc, object_uuid="t1", object_type="threat", graph=graph)
    assert issues[0].code == "schema_validation"
    graph.suggest_ref.assert_not_called()


def test_issues_from_pydantic_threat_impact_is_not_invalid_ref() -> None:
    graph = MagicMock()
    graph.suggest_ref.return_value = "ignored"
    graph.enum_resolver.suggest.return_value = None
    exc = ValidationError.from_exception_data(
        "ThreatVector",
        [
            {
                "type": "too_short",
                "loc": ("threat", "impact"),
                "msg": "List should have at least 1 item after validation, not 0",
                "input": [],
                "ctx": {"field_type": "List", "min_length": 1, "actual_length": 0},
            }
        ],
    )
    issues = issues_from_pydantic(exc, object_type="threat", graph=graph)
    assert issues[0].code == "schema_validation"


def _threat_error(metadata: dict[str, Any], **threat: Any) -> ValidationError:
    body = {
        "description": "d",
        "severity": "Significant incident",
        "impact": ["Data Breach"],
        "leverage": ["Repudiation"],
        "viability": "Likely",
        "terrain": "Endpoint workstations.",
        "surface": ["Windows::Desktop"],
        "att&ck": ["T1059"],
    }
    payload = {
        "name": "Threat",
        "criticality": "High",
        "metadata": {**metadata, "schema": "threat::1.0"},
        "threat": {**body, **threat},
    }
    with pytest.raises(ValidationError) as excinfo:
        ThreatVector.from_yaml_dict(payload)
    return excinfo.value


_PACKED = "Elevation of privilege; Repudiation"


@pytest.mark.parametrize(
    ("leverage", "field_path"),
    [
        (_PACKED, ("threat", "leverage")),
        (["Tampering", _PACKED], ("threat", "leverage", "1")),
        ("Repudiation", ("threat", "leverage")),
    ],
    ids=["packed-string", "packed-item", "single-string"],
)
def test_issues_from_pydantic_vocab_shape_errors_get_no_vocab_suggestion(
    metadata: dict[str, Any], leverage: Any, field_path: tuple[str, ...]
) -> None:
    graph = MagicMock()
    graph.enum_resolver.suggest.return_value = "Elevation of privilege"
    exc = _threat_error(metadata, leverage=leverage)
    issues = issues_from_pydantic(exc, object_type="threat", graph=graph)
    assert [(i.code, i.field_path, i.suggestion) for i in issues] == [
        ("schema_validation", field_path, None)
    ]
    graph.enum_resolver.suggest.assert_not_called()


def test_vocab_shape_rejections_key_rejected_values_by_field(metadata: dict[str, Any]) -> None:
    exc = _threat_error(
        metadata, impact="Data Breach; Identity Theft", leverage=["Spoofing", _PACKED]
    )
    assert vocab_shape_rejections(exc) == {
        (("threat", "impact"), "Data Breach; Identity Theft"),
        (("threat", "leverage"), _PACKED),
    }


def test_vocab_shape_rejections_ignore_other_schema_errors(metadata: dict[str, Any]) -> None:
    assert vocab_shape_rejections(_threat_error(metadata, impact=[])) == frozenset()


def test_is_vocab_shape_duplicate_matches_only_the_rejected_value(
    metadata: dict[str, Any],
) -> None:
    rejections = vocab_shape_rejections(_threat_error(metadata, leverage=["High", _PACKED]))

    def vocab_issue(value: str | None) -> ValidationIssue:
        return ValidationIssue(
            code="vocab_unknown",
            field_path=("threat", "leverage"),
            message="not a valid vocabulary entry",
            context={} if value is None else {"vocab": "leverage::1.0", "value": value},
        )

    assert is_vocab_shape_duplicate(vocab_issue(_PACKED), rejections)
    assert not is_vocab_shape_duplicate(vocab_issue("High"), rejections)
    assert not is_vocab_shape_duplicate(vocab_issue(None), rejections)


def test_issues_from_pydantic_objective_threats_index_is_invalid_ref() -> None:
    graph = MagicMock()
    graph.suggest_ref.return_value = "good-uuid"
    graph.enum_resolver.suggest.return_value = None
    exc = ValidationError.from_exception_data(
        "DetectionObjective",
        [
            {
                "type": "string_type",
                "loc": ("objective", "threats", 0),
                "msg": "Input should be a valid string",
                "input": "missing-threat",
            }
        ],
    )
    issues = issues_from_pydantic(exc, object_type="objective", graph=graph)
    assert issues[0].code == "invalid_ref"
    graph.suggest_ref.assert_called_once_with("threat", "missing-threat")


def test_issues_from_pydantic_detection_model_is_invalid_ref() -> None:
    graph = MagicMock()
    graph.suggest_ref.return_value = "obj-uuid"
    graph.enum_resolver.suggest.return_value = None
    exc = ValidationError.from_exception_data(
        "DetectionRule",
        [
            {
                "type": "string_type",
                "loc": ("detection_model",),
                "msg": "invalid objective ref",
                "input": "not-an-objective",
            }
        ],
    )
    issues = issues_from_pydantic(exc, object_type="rule", graph=graph)
    assert issues[0].code == "invalid_ref"
    graph.suggest_ref.assert_called_once_with("objective", "not-an-objective")


def test_issues_from_pydantic_chaining_vector_is_invalid_ref() -> None:
    graph = MagicMock()
    graph.suggest_ref.return_value = "vector-uuid"
    graph.enum_resolver.suggest.return_value = None
    exc = ValidationError.from_exception_data(
        "ThreatVector",
        [
            {
                "type": "string_type",
                "loc": ("threat", "chaining", 0, "vector"),
                "msg": "invalid vector",
                "input": "missing-vector",
            }
        ],
    )
    issues = issues_from_pydantic(exc, object_type="threat", graph=graph)
    assert issues[0].code == "invalid_ref"
    graph.suggest_ref.assert_called_once_with("threat", "missing-vector")


def test_issues_from_pydantic_nested_vocab_suggestion() -> None:
    graph = MagicMock()
    graph.suggest_ref.return_value = None
    graph.enum_resolver.suggest.return_value = "High"
    exc = ValidationError.from_exception_data(
        "ThreatVector",
        [
            {
                "type": "string_type",
                "loc": ("threat", "severity"),
                "msg": "invalid severity",
                "input": "Hgh",
            }
        ],
    )
    issues = issues_from_pydantic(exc, object_type="threat", graph=graph)
    assert issues[0].code == "vocab_unknown"
    assert issues[0].suggestion == "High"


def test_format_issues_for_console_groups_by_file() -> None:
    issues = [
        ValidationIssue(
            code="x",
            object_uuid="u1",
            field_path=("name",),
            message="bad name",
            suggestion="Better Name",
        ),
        ValidationIssue(
            code="y",
            file_path=Path("/tmp/rule.yaml"),
            field_path=(),
            message="global issue",
        ),
    ]
    output = format_issues_for_console(issues)
    assert "## u1" in output
    assert "## /tmp/rule.yaml" in output
    assert "suggestion: Better Name" in output


def test_attach_yaml_lines_without_ruamel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    issue = ValidationIssue(code="x", field_path=("name",), message="bad")
    yaml_path = tmp_path / "rule.yaml"
    yaml_path.write_text("name: x\n", encoding="utf-8")
    monkeypatch.setitem(__import__("sys").modules, "ruamel", None)
    result = attach_yaml_lines([issue], {"name": "x"}, file_path=yaml_path)
    assert result[0].yaml_line is None


def test_attach_yaml_lines_missing_file() -> None:
    issue = ValidationIssue(code="x", field_path=("name",), message="bad")
    result = attach_yaml_lines([issue], {"name": "x"}, file_path=Path("/no/such/file.yaml"))
    assert result == [issue]
