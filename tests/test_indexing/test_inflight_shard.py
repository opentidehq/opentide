"""Tests for inflight shard envelope parsing and precedence."""

from __future__ import annotations

from opentide.indexing.inflight_shard import (
    is_wrapped_shard,
    shard_change,
    shard_object,
    shard_precedence_key,
    shard_written_at,
    should_replace_object,
)


def test_is_wrapped_shard_detects_envelope() -> None:
    assert is_wrapped_shard({"schema": "inflight.shard::1.0", "object": {}})
    assert not is_wrapped_shard({"name": "raw object"})


def test_shard_object_extracts_embedded_document() -> None:
    obj = {"metadata": {"uuid": "u", "version": 1}}
    wrapped = {"schema": "inflight.shard::1.0", "object": obj}
    assert shard_object(wrapped) == obj
    assert shard_object(obj) == obj


def test_shard_change_returns_metadata() -> None:
    change = {"platform": "github", "number": 1}
    wrapped = {"schema": "inflight.shard::1.0", "change": change, "object": {}}
    assert shard_change(wrapped) == change
    assert shard_change({"name": "raw"}) is None


def test_shard_written_at_prefers_top_level_timestamp() -> None:
    wrapped = {
        "schema": "inflight.shard::1.0",
        "written_at": "2026-06-26T12:00:00+00:00",
        "change": {"recorded_at": "2026-06-26T11:00:00+00:00"},
        "object": {},
    }
    assert shard_written_at(wrapped) == "2026-06-26T12:00:00+00:00"


def test_shard_written_at_falls_back_to_recorded_at() -> None:
    wrapped = {
        "schema": "inflight.shard::1.0",
        "change": {"recorded_at": "2026-06-26T11:00:00+00:00"},
        "object": {},
    }
    assert shard_written_at(wrapped) == "2026-06-26T11:00:00+00:00"


def test_shard_precedence_key_orders_by_version_then_time() -> None:
    older = {
        "schema": "inflight.shard::1.0",
        "written_at": "2026-06-26T10:00:00+00:00",
        "object": {"metadata": {"version": 2}},
    }
    newer = {
        "schema": "inflight.shard::1.0",
        "written_at": "2026-06-26T12:00:00+00:00",
        "object": {"metadata": {"version": 2}},
    }
    assert shard_precedence_key(newer) > shard_precedence_key(older)


def test_should_replace_object_version_and_wrap_rules() -> None:
    existing = {"metadata": {"version": 1}}
    newer_shard = {
        "schema": "inflight.shard::1.0",
        "object": {"metadata": {"version": 2}},
    }
    older_shard = {
        "schema": "inflight.shard::1.0",
        "object": {"metadata": {"version": 1}},
    }
    assert should_replace_object(existing, newer_shard)
    assert should_replace_object(existing, older_shard)
    assert not should_replace_object(
        {"metadata": {"version": 2}},
        {"schema": "inflight.shard::1.0", "object": {"metadata": {"version": 1}}},
    )
