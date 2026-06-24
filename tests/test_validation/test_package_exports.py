"""Validation package lazy exports."""

from __future__ import annotations

from unittest.mock import patch

from opentide.validation import (
    ObjectRef,
    PreflightGraph,
    RuntimeEnumResolver,
    ValidationIssue,
    ValidationReport,
    ValidationScope,
    run_validation,
    validate_all_objects,
    validate_object,
    validate_raw_payload,
)


def test_validation_package_exports() -> None:
    assert ValidationIssue is not None
    assert ValidationReport is not None
    assert ValidationScope is not None
    assert run_validation is not None
    assert ObjectRef is not None
    assert PreflightGraph is not None
    assert RuntimeEnumResolver is not None


def test_validate_all_objects_delegates_to_pipeline() -> None:
    with patch(
        "opentide.validation.pipeline.validate_all_objects",
        return_value={"ok": True},
    ) as mock:
        assert validate_all_objects(repo="/tmp") == {"ok": True}
    mock.assert_called_once_with(repo="/tmp")


def test_validate_object_delegates_to_pipeline() -> None:
    with patch("opentide.validation.pipeline.validate_object", return_value=[]) as mock:
        assert validate_object({"name": "x"}) == []
    mock.assert_called_once_with({"name": "x"})


def test_validate_raw_payload_delegates_to_pipeline() -> None:
    with patch("opentide.validation.pipeline.validate_raw_payload", return_value=[]) as mock:
        assert validate_raw_payload("rule", {}) == []
    mock.assert_called_once_with("rule", {})
