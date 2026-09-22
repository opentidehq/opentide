"""MCP resources against the real tide_corpus registry (#254).

The mocked resource tests fed ``JsonSchemas.Index`` a ``{"rule": ...}`` key and
a plain dict for vocabularies, so neither the schema-id lookup nor the Pydantic
repr dump could fail.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.corpus_support import (
    CORPUS_OBJECTIVE_UUID,
    CORPUS_RULE_UUIDS,
    CORPUS_THREAT_UUID,
    clear_runtime_caches,
)

from opentide.cli.services.generation import run_generate_phase
from opentide.core.registry import OpenTide
from opentide.mcp_server import resources


@pytest.fixture
def corpus_with_schemas(tide_corpus_repo: Path) -> Path:
    """Corpus repo with generated JSON Schemas on disk."""
    run_generate_phase("schemas")
    clear_runtime_caches()
    return tide_corpus_repo


def test_schema_index_is_keyed_by_schema_id(corpus_with_schemas: Path) -> None:
    OpenTide.initialise()
    assert "rule::1.0" in OpenTide.JsonSchemas.Index
    assert "rule" not in OpenTide.JsonSchemas.Index


@pytest.mark.parametrize("requested", ["rule", "rule::1.0", "rule.1.0", "rules"])
def test_resource_schema_resolves_family_aliases(corpus_with_schemas: Path, requested: str) -> None:
    payload = json.loads(resources.resource_schema(requested))
    assert "error" not in payload
    assert payload.get("$schema") or payload.get("type") or payload.get("properties")


@pytest.mark.parametrize("family", ["threat", "objective"])
def test_resource_schema_other_families(corpus_with_schemas: Path, family: str) -> None:
    payload = json.loads(resources.resource_schema(family))
    assert "error" not in payload


def test_resource_schema_reports_unknown_family(corpus_with_schemas: Path) -> None:
    payload = json.loads(resources.resource_schema("nonexistent"))
    assert "error" in payload
    assert "rule::1.0" in payload["available"]


def test_resource_schema_without_generated_schemas_explains_itself(
    tide_corpus_repo: Path,
) -> None:
    payload = json.loads(resources.resource_schema("rule"))
    assert "error" in payload
    assert "generate schemas" in payload["hint"]


def test_resource_vocabularies_are_json_objects(tide_corpus_repo: Path) -> None:
    payload = json.loads(resources.resource_vocabularies())
    assert payload, "expected bundled vocabularies"
    for name, entry in payload.items():
        assert isinstance(entry, dict), f"{name} serialised as {type(entry).__name__}"
        assert "metadata" in entry
        assert isinstance(entry["metadata"], dict)
        assert isinstance(entry.get("entries"), dict)


def test_resource_vocabulary_single_entry_is_json(tide_corpus_repo: Path) -> None:
    payload = json.loads(resources.resource_vocabulary("actors"))
    assert isinstance(payload, dict)
    assert payload["metadata"]["field"] == "actors"
    assert "VocabularyMetadata(" not in json.dumps(payload)


def test_resource_vocabulary_unknown_name_reports_available(tide_corpus_repo: Path) -> None:
    payload = json.loads(resources.resource_vocabulary("nonexistent"))
    assert "error" in payload
    assert "actors" in payload["available"]


def test_resource_object_bodies_round_trip(tide_corpus_repo: Path) -> None:
    rule = json.loads(resources.resource_rule(CORPUS_RULE_UUIDS["sentinel"]))
    threat = json.loads(resources.resource_threat(CORPUS_THREAT_UUID))
    objective = json.loads(resources.resource_objective(CORPUS_OBJECTIVE_UUID))
    assert rule["metadata"]["uuid"] == CORPUS_RULE_UUIDS["sentinel"]
    assert threat["threat"]["actors"]
    assert objective["metadata"]["uuid"] == CORPUS_OBJECTIVE_UUID


def test_resource_lists_cover_every_family(tide_corpus_repo: Path) -> None:
    rules = json.loads(resources.resource_rules())
    threats = json.loads(resources.resource_threats())
    objectives = json.loads(resources.resource_objectives())
    assert set(rules) >= set(CORPUS_RULE_UUIDS.values())
    assert CORPUS_THREAT_UUID in threats
    assert CORPUS_OBJECTIVE_UUID in objectives


def test_resource_index_is_json(tide_corpus_repo: Path) -> None:
    payload = json.loads(resources.resource_index())
    assert isinstance(payload, dict)
    assert "paths" in payload
