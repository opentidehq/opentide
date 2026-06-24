"""Tests for validation error transformation helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, Field, ValidationError

from opentide.validation.errors import (
    attach_yaml_lines,
    format_issues_for_console,
    issues_from_pydantic,
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
                "loc": ("objective", "threat"),
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
