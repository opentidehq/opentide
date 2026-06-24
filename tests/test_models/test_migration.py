"""Schema revision migration helpers."""

from __future__ import annotations

from opentide.models.migration import stamp_schema_identifier


def test_stamp_schema_identifier_empty_id_returns_unchanged() -> None:
    body = {"metadata": {"uuid": "u1"}}
    assert stamp_schema_identifier(body, "") is body


def test_stamp_schema_identifier_updates_metadata() -> None:
    body = {"metadata": {"uuid": "u1"}, "name": "Rule"}
    result = stamp_schema_identifier(body, "rule::1.0")
    assert result["metadata"]["schema"] == "rule::1.0"
    assert result is not body
    assert body["metadata"] == {"uuid": "u1"}


def test_stamp_schema_identifier_updates_legacy_meta() -> None:
    body = {"meta": {"version": 1}, "name": "Threat"}
    result = stamp_schema_identifier(body, "threat::1.0")
    assert result["meta"]["schema"] == "threat::1.0"


def test_stamp_schema_identifier_creates_metadata_when_missing() -> None:
    body = {"name": "Objective"}
    result = stamp_schema_identifier(body, "objective::1.0")
    assert result["metadata"] == {"schema": "objective::1.0"}
