"""Tests for deprecated-field validation warnings."""

from __future__ import annotations

from opentide.validation.deprecated_fields import (
    resolve_metaschema,
    validate_deprecated_fields_from_metaschema,
)


def test_resolve_metaschema_prefers_metadata_schema() -> None:
    metaschemas = {
        "rule::1.0": {"properties": {"meta": {"tide.meta.deprecation": "old"}}},
        "rule::1.1": {"properties": {"metadata": {"type": "object"}}},
    }
    payload = {"metadata": {"schema": "rule::1.0"}, "meta": "legacy"}
    schema = resolve_metaschema(metaschemas, payload, "rule")
    assert schema is metaschemas["rule::1.0"]


def test_deprecated_field_emits_warning() -> None:
    metaschemas = {
        "rule::1.0": {
            "properties": {
                "meta": {"tide.meta.deprecation": "Use metadata keyword instead"},
            }
        }
    }
    payload = {"metadata": {"schema": "rule::1.0"}, "meta": {"uuid": "x"}}
    issues = validate_deprecated_fields_from_metaschema(
        payload,
        metaschemas,
        "rule",
        object_uuid="uuid-1",
    )
    assert len(issues) == 1
    assert issues[0].severity == "warning"
    assert issues[0].code == "deprecated_field"
