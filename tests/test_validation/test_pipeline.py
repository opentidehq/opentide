"""Tests for validation pipeline helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.validation import pipeline
from opentide.validation.pipeline import (
    validate_all_objects,
    validate_object,
    validate_raw_payload,
)


def test_validate_object_unknown_type() -> None:
    result = validate_object(MagicMock(), "unknown")
    assert not result.ok


def test_validate_raw_payload_unknown_type() -> None:
    result = validate_raw_payload({}, "unknown")
    assert not result.ok


def test_validate_raw_payload_invalid_rule() -> None:
    result = validate_raw_payload({"name": "incomplete"}, "rule")
    assert not result.ok


def test_validate_all_objects_empty_index() -> None:
    assert validate_all_objects({}) == {}


def test_validate_all_objects_delegates_to_session() -> None:
    report = MagicMock()
    report.legacy_errors_by_uuid.return_value = {"u1": ["err"]}
    with patch("opentide.validation.session.run_validation", return_value=report):
        errors = validate_all_objects({"rule": {"u1": {}}})
    assert errors == {"u1": ["err"]}


def test_validate_object_revalidates_model() -> None:
    model = MagicMock()
    model.model_dump.return_value = {"name": "Test"}
    mock_cls = MagicMock()
    mock_cls.model_validate.return_value = model
    with patch.object(pipeline, "_MODEL_BY_TYPE", {"rule": mock_cls}):
        result = validate_object(model, "rule")
    assert result.ok
