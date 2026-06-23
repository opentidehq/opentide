"""Validation pipeline behaviour."""

from __future__ import annotations

from typing import Any

from opentide.models.rule import DetectionRule
from opentide.validation.pipeline import validate_all_objects, validate_object, validate_raw_payload


def test_validate_raw_payload_rule_ok(rule_payload: dict[str, Any]) -> None:
    result = validate_raw_payload(rule_payload, "rule")
    assert result.ok is True


def test_validate_raw_payload_unknown_type() -> None:
    result = validate_raw_payload({}, "unknown")
    assert result.ok is False
    assert "Unknown object type" in result.errors[0]


def test_validate_raw_payload_validation_error(metadata: dict[str, Any]) -> None:
    invalid = {"name": "Broken", "metadata": metadata}
    result = validate_raw_payload(invalid, "rule")
    assert result.ok is False
    assert result.errors


def test_validate_object_unknown_type(rule_payload: dict[str, Any]) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    result = validate_object(rule, "unknown")
    assert result.ok is False
    assert "Unknown object type" in result.errors[0]


def test_validate_object_roundtrip(rule_payload: dict[str, Any]) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    result = validate_object(rule, "rule")
    assert result.ok is True


def test_validate_all_objects_empty() -> None:
    errors = validate_all_objects({"rule": {}, "objective": {}, "threat": {}})
    assert errors == {}
