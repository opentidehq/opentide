"""Tests for validation pipeline helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from opentide.core.registry import OpenTide
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.validation.pipeline import (
    validate_all_objects,
    validate_object,
    validate_raw_payload,
)

# Verbatim copies of the versioning examples in OpenTideHQ/specifications
# fixtures/{valid,invalid} at d270475c1729af4a3ef513ff5ba26087c21547ea.
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "specifications" / "versioning"


def _fixture(name: str) -> dict[str, Any]:
    return yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))


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


@pytest.mark.parametrize("name", ["valid/rule-1.0.yaml", "valid/rule-1.1.yaml"])
def test_validate_rule_follows_metadata_schema(name: str) -> None:
    body = _fixture(name)
    result = OpenTide.validate_rule(load_rule_from_dict(body))
    assert result.ok, result.errors
    assert validate_raw_payload(body, "rule").ok


def test_rule_10_with_reviewed_still_fails() -> None:
    result = validate_raw_payload(_fixture("invalid/rule-1.0-reviewed.yaml"), "rule")
    assert not result.ok
    assert result.errors == ["('metadata', 'reviewed'): Extra inputs are not permitted"]


def test_missing_schema_is_schema_missing() -> None:
    body = _fixture("valid/rule-1.1.yaml")
    del body["metadata"]["schema"]
    result = validate_raw_payload(body, "rule")
    assert not result.ok
    assert result.errors == ["schema_missing: missing metadata.schema on object"]


def test_metadata_that_is_not_a_mapping_is_a_shape_error() -> None:
    body = _fixture("valid/rule-1.1.yaml")
    body["metadata"] = "rule::1.1"
    result = validate_raw_payload(body, "rule")
    assert not result.ok
    assert result.errors == ["('metadata',): Input should be a valid dictionary"]


def test_unknown_schema_is_not_the_newest_revision() -> None:
    result = validate_raw_payload(_fixture("invalid/rule-unknown-schema.yaml"), "rule")
    assert not result.ok
    assert result.errors == ["('metadata', 'schema'): unknown schema identifier: 'rule::9.9'"]


def test_schema_of_another_family_is_rejected() -> None:
    body = _fixture("valid/rule-1.0.yaml")
    body["metadata"]["schema"] = "threat::1.0"
    result = validate_raw_payload(body, "rule")
    assert not result.ok
    assert result.errors == [
        "('metadata', 'schema'): 'threat::1.0' is not a rule schema identifier"
    ]


def test_a_lookup_error_from_the_model_is_not_blamed_on_metadata_schema() -> None:
    """Only schema resolution maps to ``('metadata', 'schema')``."""
    with (
        patch("opentide.loading.object_loader._instantiate_model", side_effect=KeyError("tlp")),
        pytest.raises(KeyError, match="tlp"),
    ):
        validate_raw_payload(_fixture("valid/rule-1.0.yaml"), "rule")
