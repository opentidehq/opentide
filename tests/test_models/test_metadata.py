"""Metadata and reference models."""

from __future__ import annotations

from opentide.models.metadata import ObjectReferences, Organisation


def test_object_references_coerce_public_keys() -> None:
    data = ObjectReferences.coerce_public_keys({"public": {"1": "ref"}})
    refs = ObjectReferences.model_validate(data)
    assert refs.public == {1: "ref"}


def test_organisation_model() -> None:
    org = Organisation(uuid="u", name="Org")
    assert org.name == "Org"
