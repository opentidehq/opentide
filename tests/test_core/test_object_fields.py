"""Shared object field extraction used by CLI info and MCP catalog.

The extraction is anchored to the Pydantic models: the technique / actor /
configuration fields are DERIVED from the models that declare them (tagged with
:class:`~opentide.models.base.FieldRole`), selected per object by the body's
``metadata.schema`` identifier. These tests pin that contract — including that
the legacy ``attack`` key and the flat ``tags`` tolerance are gone (0.14.1) — and
that the field names are derived rather than hardcoded.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from opentide.core.object_fields import (
    as_body,
    matched_techniques,
    matches_actor,
    matches_platform,
    matches_technique,
    object_actors,
    object_platforms,
    object_techniques,
    technique_covers,
)
from opentide.models.base import FieldRole, TideField, TideModel


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


# --- Techniques, resolved per the body's model -----------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            {"metadata": {"schema": "rule::1.0"}, "techniques": ["T1059"]},
            id="rule-top-level-techniques",
        ),
        pytest.param(
            {"metadata": {"schema": "threat::1.0"}, "threat": {"mitre_attack": ["T1059"]}},
            id="threat-nested-mitre_attack",
        ),
        pytest.param(
            {"metadata": {"schema": "objective::1.0"}, "objective": {"mitre_attack": ["T1059"]}},
            id="objective-nested-mitre_attack",
        ),
    ],
)
def test_object_techniques_reads_the_model_declared_field(body: dict[str, Any]) -> None:
    assert object_techniques(body) == {"T1059"}


def test_object_techniques_does_not_cross_field_to_model() -> None:
    """A rule is not scanned for ``mitre_attack`` and a threat not for ``techniques``.

    The old union-of-keys scanner read every key in every section; the
    model-anchored resolver reads only the field the identified model declares.
    """
    rule_with_threat_key = {"metadata": {"schema": "rule::1.0"}, "mitre_attack": ["T1059"]}
    assert object_techniques(rule_with_threat_key) == set()
    threat_with_rule_key = {"metadata": {"schema": "threat::1.0"}, "techniques": ["T1059"]}
    assert object_techniques(threat_with_rule_key) == set()


def test_object_techniques_rejects_legacy_attack_key() -> None:
    """``attack`` is declared by no model, so it is not accepted on a current object (0.14.1)."""
    body = {"metadata": {"schema": "rule::1.0"}, "attack": ["T1059"], "tags": {"attack": ["T1003"]}}
    assert object_techniques(body) == set()


def test_object_techniques_rejects_flat_tags_section() -> None:
    """The legacy ``tags`` section is not a model field, so it is not scanned (0.14.1)."""
    body = {"metadata": {"schema": "rule::1.0"}, "tags": {"techniques": ["T1059"]}}
    assert object_techniques(body) == set()


def test_object_techniques_derives_field_names_without_a_hardcoded_tuple() -> None:
    """Field names are DERIVED from the models.

    Register a throwaway technique-bearing model with a differently NAMED field
    and assert extraction picks it up with no change to ``object_fields``. This
    is the negative control: a resolver that read a hardcoded ``("techniques",
    "mitre_attack")`` tuple could not see ``ttp_refs`` and would return an empty
    set here, failing the test.
    """
    from opentide.models.schema_registry import register_model, unregister_model

    class _TrialRule(TideModel):
        __schema_identifier__ = "trial::9.9"
        ttp_refs: list[str] = TideField(default_factory=list, role=FieldRole.TECHNIQUES)

    register_model(_TrialRule)
    try:
        body = {"metadata": {"schema": "trial::9.9"}, "ttp_refs": ["T1566"]}
        assert object_techniques(body) == {"T1566"}
    finally:
        unregister_model("trial::9.9")
        # Drop the memoised paths for the throwaway schema.
        from opentide.core.object_fields import _role_paths

        _role_paths.cache_clear()


# --- Fallback for a body without a resolvable schema -----------------------


def test_object_techniques_falls_back_to_model_union_without_schema() -> None:
    """A body with no resolvable schema is read against the union of model paths,
    not ignored and not against a legacy key tuple."""
    assert object_techniques({"techniques": ["T1059"]}) == {"T1059"}
    assert object_techniques({"threat": {"mitre_attack": ["T1003"]}}) == {"T1003"}
    assert object_techniques({"objective": {"mitre_attack": ["T1566"]}}) == {"T1566"}
    # Even in fallback, a non-model key such as the legacy ``attack`` is absent.
    assert object_techniques({"tags": {"attack": ["T1059"]}}) == set()


# --- Technique matching semantics (unchanged) ------------------------------


def test_matches_technique_is_case_insensitive() -> None:
    body = {"metadata": {"schema": "rule::1.0"}, "techniques": ["T1059"]}
    assert matches_technique(body, "t1059")
    assert not matches_technique(body, "T1003")


def test_empty_technique_matches_everything() -> None:
    assert matches_technique({}, "")


@pytest.mark.parametrize(
    ("requested", "candidate", "expected"),
    [
        ("T1059", "T1059", True),
        ("T1059", "T1059.001", True),
        ("t1059", "T1059.001", True),
        ("T1059.001", "T1059", False),
        ("T1059.001", "T1059.003", False),
        ("T105", "T1059", False),
        ("T105", "T1059.001", False),
        ("", "T1059", False),
    ],
)
def test_technique_covers_parent_to_sub_technique_only(
    requested: str, candidate: str, expected: bool
) -> None:
    assert technique_covers(requested, candidate) is expected


def test_matched_techniques_reports_the_sub_techniques_that_answered() -> None:
    body = {"metadata": {"schema": "rule::1.0"}, "techniques": ["T1059.001", "T1059.003", "T1003"]}
    assert matched_techniques(body, "T1059") == {"T1059.001", "T1059.003"}
    assert matches_technique(body, "T1059")
    assert not matches_technique(
        {"metadata": {"schema": "rule::1.0"}, "techniques": ["T1059"]}, "T1059.001"
    )


# --- Actors ----------------------------------------------------------------


def test_object_actors_expands_namespaced_names() -> None:
    body = {
        "metadata": {"schema": "threat::1.0"},
        "threat": {"actors": [{"name": "att&ck::G0006"}]},
    }
    assert object_actors(body) == {"att&ck::g0006", "g0006"}


def test_object_actors_reads_nested_actor_name_field() -> None:
    """Actors are read from ``threat.actors[].name`` — the model's nested path."""
    body = {"metadata": {"schema": "threat::1.0"}, "threat": {"actors": [{"name": "APT29"}]}}
    assert object_actors(body) == {"apt29"}


def test_matches_actor_on_bare_and_namespaced_form() -> None:
    body = {
        "metadata": {"schema": "threat::1.0"},
        "threat": {"actors": [{"name": "att&ck::G0006"}]},
    }
    assert matches_actor(body, "G0006")
    assert matches_actor(body, "att&ck::G0006")
    assert not matches_actor(body, "G0007")


# --- Platforms -------------------------------------------------------------


def test_object_platforms_reads_configuration_keys() -> None:
    body = {"metadata": {"schema": "rule::1.0"}, "configurations": {"sentinel": {}, "Splunk": {}}}
    assert object_platforms(body) == {"sentinel", "splunk"}


def test_object_platforms_reads_platforms_field() -> None:
    body = {"metadata": {"schema": "rule::1.0"}, "platforms": {"sentinel_one": {}}}
    assert object_platforms(body) == {"sentinel_one"}


def test_matches_platform_does_not_substring_match() -> None:
    """``sentinel`` must not match a ``sentinel_one`` configuration (#253)."""
    s1 = {"metadata": {"schema": "rule::1.0"}, "configurations": {"sentinel_one": {}}}
    assert not matches_platform(s1, "sentinel")
    assert matches_platform(s1, "sentinel_one")


def test_matches_platform_empty_needle_matches_everything() -> None:
    assert matches_platform({"configurations": {}}, "")
