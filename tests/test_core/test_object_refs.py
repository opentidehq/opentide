"""Unit tests for opentide.core.object_refs."""

from __future__ import annotations

import pytest

from opentide.core.object_refs import object_name, object_uuid


def test_object_uuid_from_top_level() -> None:
    body = {"uuid": "00000000-0000-4000-8000-000000000099"}
    assert object_uuid(body) == "00000000-0000-4000-8000-000000000099"


def test_object_uuid_from_metadata(rule_payload: dict) -> None:
    assert object_uuid(rule_payload) == rule_payload["metadata"]["uuid"]


def test_object_uuid_missing_raises() -> None:
    with pytest.raises(KeyError, match="uuid"):
        object_uuid({"name": "orphan"})


def test_object_name_from_top_level() -> None:
    body = {"name": "Direct Name"}
    assert object_name(body) == "Direct Name"


def test_object_name_from_metadata(rule_payload: dict) -> None:
    rule_payload["metadata"]["name"] = "Metadata Name"
    assert object_name(rule_payload) == "Metadata Name"


def test_object_name_missing_raises() -> None:
    with pytest.raises(KeyError, match="name"):
        object_name({"metadata": {"uuid": "x"}})
