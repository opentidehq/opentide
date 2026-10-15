"""opentide.schema.json router: one revision schema per object (issue #550)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

import pytest
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT202012

from opentide.generation.pydantic_schemas import generate_schema_for_identifier
from opentide.generation.router_schema import build_opentide_router, export_opentide_router
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.models.schema_registry import identifiers_for_families, registered_identifiers
from opentide.registry.artifacts import schema_artifact_name

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests/fixtures/tide_corpus/current/Objects"
ROUTER = "opentide.schema.json"


def _load(path: Path) -> dict[str, Any]:
    # JSON round trip turns YAML dates into the strings an editor sees.
    return json.loads(json.dumps(yaml.safe_load(path.read_text(encoding="utf-8")), default=str))


def _with_schema(body: dict[str, Any], schema_id: str, **metadata: Any) -> dict[str, Any]:
    result = copy.deepcopy(body)
    result["metadata"] = {**result["metadata"], "schema": schema_id, **metadata}
    return result


def _valid_bodies() -> dict[str, dict[str, Any]]:
    threat = _load(CORPUS / "Threat Vectors/threat-0001-simulated-actor.yaml")
    objective = _load(CORPUS / "Detection Objectives/objective-0001-credential-access.yaml")
    # The corpus keeps a legacy root `composition` the model drops on load.
    objective.pop("composition", None)
    rule = _load(CORPUS / "Detection Rules/rule-0001-sentinel-kql.yaml")
    return {
        "threat::1.0": threat,
        "objective::1.0": objective,
        "rule::1.0": rule,
        "rule::1.1": _with_schema(rule, "rule::1.1", reviewed="2026-10-01"),
    }


VALID = _valid_bodies()


@pytest.fixture(scope="module")
def schema_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Revision schemas plus the router, laid out like ``.opentide/schemas/``."""
    directory = tmp_path_factory.mktemp("schemas")
    for schema_id in identifiers_for_families(CORE_OBJECT_TYPES):
        schema = generate_schema_for_identifier(schema_id, enrich=False)
        (directory / schema_artifact_name(schema_id)).write_text(json.dumps(schema), "utf-8")
    export_opentide_router(directory / ROUTER)
    return directory


def _registry(directory: Path) -> Registry:
    """Resolve only files under *directory*; any other URI fails the lookup."""

    def retrieve(uri: str) -> Resource:
        path = Path(url2pathname(urlparse(uri).path))
        if path.parent != directory.resolve():
            raise LookupError(uri)
        return Resource.from_contents(
            json.loads(path.read_text(encoding="utf-8")), default_specification=DRAFT202012
        )

    return Registry(retrieve=retrieve)


@pytest.fixture(scope="module")
def router_validator(schema_dir: Path) -> Draft202012Validator:
    # Reference the router by its file URI so relative refs resolve against it,
    # exactly as an editor that loaded it from disk does.
    entry = {"$ref": (schema_dir / ROUTER).resolve().as_uri()}
    return Draft202012Validator(entry, registry=_registry(schema_dir))


def _matching_branches(router: dict[str, Any], body: dict[str, Any]) -> list[str]:
    return [
        branch["then"]["$ref"]
        for branch in router["allOf"]
        if Draft202012Validator(branch["if"]).is_valid(body)
    ]


def test_every_routed_identifier_has_a_valid_fixture() -> None:
    assert set(VALID) == set(identifiers_for_families(CORE_OBJECT_TYPES))


def test_router_has_no_remote_id_and_relative_sibling_refs() -> None:
    router = build_opentide_router()
    assert "$id" not in router
    assert router["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    refs = [branch["then"]["$ref"] for branch in router["allOf"]]
    assert refs == [schema_artifact_name(sid) for sid in sorted(VALID)]
    assert all("/" not in ref for ref in refs)


def test_router_offers_object_identifiers_on_metadata_schema() -> None:
    schema = build_opentide_router()["properties"]["metadata"]["properties"]["schema"]
    assert schema["enum"] == identifiers_for_families(CORE_OBJECT_TYPES)
    assert len(schema["enumDescriptions"]) == len(schema["enum"])
    # visibility::1.0 is configuration, not an object, and has no metadata.schema.
    assert "visibility::1.0" in registered_identifiers()
    assert "visibility::1.0" not in schema["enum"]


@pytest.mark.parametrize("schema_id", sorted(VALID))
def test_router_validates_each_revision_through_exactly_one_branch(
    schema_id: str, schema_dir: Path, router_validator: Draft202012Validator
) -> None:
    body = VALID[schema_id]
    revision = json.loads((schema_dir / schema_artifact_name(schema_id)).read_text("utf-8"))
    assert list(Draft202012Validator(revision).iter_errors(body)) == []
    assert _matching_branches(build_opentide_router(), body) == [schema_artifact_name(schema_id)]
    assert list(router_validator.iter_errors(body)) == []


def test_router_applies_the_named_revision_not_its_sibling(
    router_validator: Draft202012Validator,
) -> None:
    reviewed_on_1_0 = _with_schema(VALID["rule::1.0"], "rule::1.0", reviewed="2026-10-01")
    errors = list(router_validator.iter_errors(reviewed_on_1_0))
    assert errors
    assert all("reviewed" in error.message for error in errors)


def test_router_rejects_unknown_identifier_on_metadata_schema(
    router_validator: Draft202012Validator,
) -> None:
    body = _with_schema(VALID["rule::1.0"], "rule::9.9")
    assert _matching_branches(build_opentide_router(), body) == []
    errors = list(router_validator.iter_errors(body))
    assert [(list(error.absolute_path), error.validator) for error in errors] == [
        (["metadata", "schema"], "enum")
    ]


def test_router_rejects_wrong_family_identifier(router_validator: Draft202012Validator) -> None:
    body = _with_schema(VALID["rule::1.0"], "threat::1.0")
    assert _matching_branches(build_opentide_router(), body) == ["threat.1.0.schema.json"]
    assert not router_validator.is_valid(body)


@pytest.mark.parametrize(
    "body",
    [{"name": "no metadata"}, {"metadata": "rule::1.1"}, {"metadata": {"uuid": "x"}}, "scalar"],
)
def test_router_routes_nothing_without_a_schema_identifier(
    body: Any, router_validator: Draft202012Validator
) -> None:
    assert _matching_branches(build_opentide_router(), body) == []
    assert not router_validator.is_valid(body)


def test_router_refs_do_not_leave_the_schema_dir(schema_dir: Path, tmp_path: Path) -> None:
    lonely = tmp_path / ROUTER
    lonely.write_text((schema_dir / ROUTER).read_text("utf-8"), "utf-8")
    validator = Draft202012Validator({"$ref": lonely.as_uri()}, registry=_registry(tmp_path))
    with pytest.raises(Unresolvable):
        validator.validate(VALID["rule::1.1"])
