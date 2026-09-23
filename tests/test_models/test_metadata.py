"""Metadata and reference models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import (
    CORPUS_OBJECTIVE_UUID,
    CORPUS_RULE_UUIDS,
    CORPUS_THREAT_UUID,
)

from opentide.models.metadata import ObjectMetadata, ObjectReferences, Organisation


def test_object_references_coerce_public_keys() -> None:
    data = ObjectReferences.coerce_public_keys({"public": {"1": "ref"}})
    refs = ObjectReferences.model_validate(data)
    assert refs.public == {1: "ref"}


def test_organisation_model() -> None:
    org = Organisation(uuid="u", name="Org")
    assert org.name == "Org"


def test_schema_attribute_is_the_schema_identifier(metadata: dict[str, Any]) -> None:
    """Issue #298: `.schema` was Pydantic's deprecated `BaseModel.schema` classmethod."""
    loaded = ObjectMetadata.model_validate(metadata)
    assert isinstance(loaded.schema, str)
    assert loaded.schema == "rule::1.0"
    assert loaded.schema == loaded.schema_id


@pytest.mark.parametrize("key", ["schema", "schema_id"])
def test_schema_identifier_validates_by_alias_and_by_name(
    metadata: dict[str, Any], key: str
) -> None:
    payload = {name: value for name, value in metadata.items() if name != "schema"}
    payload[key] = "objective::1.0"
    loaded = ObjectMetadata.model_validate(payload)
    assert loaded.schema_id == "objective::1.0"
    assert loaded.schema == "objective::1.0"


def test_schema_identifier_keeps_its_yaml_key_on_the_way_out(metadata: dict[str, Any]) -> None:
    loaded = ObjectMetadata.model_validate(metadata)
    assert loaded.model_dump(by_alias=True)["schema"] == "rule::1.0"
    assert loaded.model_dump()["schema_id"] == "rule::1.0"
    assert "schema" not in loaded.model_dump()
    assert "schema" in ObjectMetadata.model_json_schema(by_alias=True)["properties"]


def test_unknown_schema_identifier_is_still_rejected(metadata: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="unknown schema identifier"):
        ObjectMetadata.model_validate({**metadata, "schema": "rule:1.0"})


@pytest.mark.parametrize(
    ("collection", "uuid", "identifier"),
    [
        ("Rules", CORPUS_RULE_UUIDS["sentinel"], "rule::1.0"),
        ("Objectives", CORPUS_OBJECTIVE_UUID, "objective::1.0"),
        ("Threats", CORPUS_THREAT_UUID, "threat::1.0"),
    ],
)
def test_loaded_objects_expose_their_schema_identifier(
    tide_corpus_repo: Path, collection: str, uuid: str, identifier: str
) -> None:
    """The attribute docs/sdk/models.md prints, read off an object the registry loaded."""
    from opentide import OpenTide

    OpenTide.initialise()
    loaded = getattr(OpenTide, collection)[uuid]
    assert isinstance(loaded.metadata.schema, str)
    assert loaded.metadata.schema == identifier
    assert loaded.metadata.schema_id == identifier
