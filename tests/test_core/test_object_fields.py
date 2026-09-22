"""Shared object field extraction used by CLI info and MCP catalog."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from opentide.core.object_fields import (
    as_body,
    matches_actor,
    matches_platform,
    matches_technique,
    object_actors,
    object_platforms,
    object_techniques,
)


class _Rule(BaseModel):
    name: str
    techniques: list[str]


def test_as_body_passes_dicts_through() -> None:
    body = {"name": "x"}
    assert as_body(body) is body


def test_as_body_dumps_pydantic_models() -> None:
    assert as_body(_Rule(name="x", techniques=["T1059"])) == {
        "name": "x",
        "techniques": ["T1059"],
    }


def test_as_body_rejects_scalars() -> None:
    assert as_body("not an object") == {}
    assert as_body(None) == {}


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"techniques": ["T1059"]}, id="top-level"),
        pytest.param({"tags": {"techniques": ["T1059"]}}, id="tags-techniques"),
        pytest.param({"tags": {"attack": ["T1059"]}}, id="tags-attack"),
        pytest.param({"threat": {"att&ck": ["T1059"]}}, id="threat-attack"),
    ],
)
def test_object_techniques_unions_every_location(body: dict[str, Any]) -> None:
    assert object_techniques(body) == {"T1059"}


def test_object_techniques_merges_duplicate_locations() -> None:
    body = {"techniques": ["T1059"], "tags": {"attack": ["T1003", "T1059"]}}
    assert object_techniques(body) == {"T1059", "T1003"}


def test_object_techniques_ignores_non_mapping_tags() -> None:
    assert object_techniques({"tags": ["T1059"], "techniques": ["T1003"]}) == {"T1003"}


def test_matches_technique_is_case_insensitive() -> None:
    body = {"techniques": ["T1059"]}
    assert matches_technique(body, "t1059")
    assert not matches_technique(body, "T1003")


def test_empty_technique_matches_everything() -> None:
    assert matches_technique({}, "")


def test_object_actors_expands_namespaced_names() -> None:
    body = {"threat": {"actors": [{"name": "att&ck::G0006"}]}}
    assert object_actors(body) == {"att&ck::g0006", "g0006"}


def test_object_actors_accepts_plain_strings_and_tags() -> None:
    assert object_actors({"tags": {"actors": ["APT29"]}}) == {"apt29"}


def test_matches_actor_on_bare_and_namespaced_form() -> None:
    body = {"threat": {"actors": [{"name": "att&ck::G0006"}]}}
    assert matches_actor(body, "G0006")
    assert matches_actor(body, "att&ck::G0006")
    assert not matches_actor(body, "G0007")


def test_object_platforms_reads_configuration_keys() -> None:
    body = {"configurations": {"sentinel": {}, "Splunk": {}}}
    assert object_platforms(body) == {"sentinel", "splunk"}


def test_object_platforms_reads_legacy_platforms_key() -> None:
    assert object_platforms({"platforms": {"sentinel_one": {}}}) == {"sentinel_one"}


def test_matches_platform_does_not_substring_match() -> None:
    """``sentinel`` must not match a ``sentinel_one`` configuration (#253)."""
    s1 = {"configurations": {"sentinel_one": {}}}
    assert not matches_platform(s1, "sentinel")
    assert matches_platform(s1, "sentinel_one")


def test_matches_platform_empty_needle_matches_everything() -> None:
    assert matches_platform({"configurations": {}}, "")
