"""Generated revision schemas agree with the models on shipped fixtures (#551, #552).

Schemas are generated with enrichment (vocabularies, definitions) against the
tide_corpus workspace, the same path ``opentide generate schemas`` takes. The
enrich=False shortcut skips the definition pipeline that dropped
``metadata.reviewed`` from ``rule::1.1``.
"""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from opentide.generation.pydantic_schemas import generate_schema_for_identifier
from opentide.loading.object_loader import load_object
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.models.schema_registry import identifiers_for_families

REVIEWED = [
    "2026-10-15",
    "2026-10-15T08:30:00Z",
    "2026-10-15T08:30:00+02:00",
    "2026-10-15 08:30:00Z",
]
EFFORT = [(3, True), (0, True), (10, True), (None, True)] + [
    (value, False) for value in ("3", "Regular", True, 2.5)
]
NOT_REVIEWED = ["yesterday", "2026-13-45", "2026-10-15T08:30:00"]


# jsonschema checks `date-time` only with an optional dependency. Stand in for the
# editor's RFC 3339 check: `T` separator, seconds, and a mandatory offset.
_FORMATS: FormatChecker = copy.deepcopy(Draft202012Validator.FORMAT_CHECKER)
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$")


@_FORMATS.checks("date-time", raises=ValueError)
def _is_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if not _RFC3339.fullmatch(value):
        return False
    datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    return True


def _load(path: Path) -> dict[str, Any]:
    # JSON round trip turns YAML dates into the strings an editor sees.
    return json.loads(json.dumps(yaml.safe_load(path.read_text(encoding="utf-8")), default=str))


def _with_metadata(body: dict[str, Any], **metadata: Any) -> dict[str, Any]:
    result = copy.deepcopy(body)
    result["metadata"] = {**result["metadata"], **metadata}
    return result


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Enriched schemas for every revision, and fixtures from the tide_corpus workspace."""
    from tests.corpus_support import clear_runtime_caches, materialise_corpus

    repo = materialise_corpus(tmp_path_factory.mktemp("revisions") / "corpus")
    patch = pytest.MonkeyPatch()
    patch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    patch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    clear_runtime_caches()
    try:
        schemas = {
            schema_id: generate_schema_for_identifier(schema_id)
            for schema_id in identifiers_for_families(CORE_OBJECT_TYPES)
        }
    finally:
        patch.undo()
        clear_runtime_caches()
    objects = repo / "objects"
    objective = _load(next((objects / "objectives").rglob("*.yaml")))
    # The model drops a legacy root `composition`; the editor schema does not list it.
    objective.pop("composition", None)
    signals = objective["objective"]["signals"]
    signals[0] = {**signals[0], "effort": 3}
    rule = _load(next((objects / "rules").rglob("rule-0001-*.yaml")))
    return {
        "schemas": schemas,
        "valid": {
            "threat::1.0": _load(next((objects / "threats").rglob("*.yaml"))),
            "objective::1.0": objective,
            "rule::1.0": rule,
            "rule::1.1": _with_metadata(rule, schema="rule::1.1", reviewed="2026-10-15"),
        },
    }


def test_every_revision_has_a_valid_fixture(corpus: dict[str, Any]) -> None:
    assert set(corpus["valid"]) == set(corpus["schemas"])


@pytest.mark.parametrize("schema_id", identifiers_for_families(CORE_OBJECT_TYPES))
def test_generated_schema_accepts_valid_fixture(schema_id: str, corpus: dict[str, Any]) -> None:
    body = corpus["valid"][schema_id]
    load_object(body)
    errors = list(Draft202012Validator(corpus["schemas"][schema_id]).iter_errors(body))
    assert [error.message for error in errors] == []


def test_rule_1_1_schema_declares_reviewed_and_1_0_does_not(corpus: dict[str, Any]) -> None:
    metadata = {
        schema_id: corpus["schemas"][schema_id]["properties"]["metadata"]
        for schema_id in ("rule::1.0", "rule::1.1")
    }
    assert "reviewed" in metadata["rule::1.1"]["properties"]
    assert "reviewed" not in metadata["rule::1.0"]["properties"]
    assert metadata["rule::1.0"]["additionalProperties"] is False
    for schema_id, node in metadata.items():
        assert node["properties"]["schema"]["const"] == schema_id
    # Everything but `reviewed` (and the pinned identifier, and the hover text
    # naming both) matches rule::1.0.
    current = copy.deepcopy(corpus["schemas"]["rule::1.1"])
    legacy = copy.deepcopy(corpus["schemas"]["rule::1.0"])
    current_metadata = current["properties"]["metadata"]
    legacy_metadata = legacy["properties"]["metadata"]
    del current_metadata["properties"]["reviewed"]
    current_metadata["properties"]["schema"] = legacy_metadata["properties"]["schema"]
    for annotation in ("description", "markdownDescription"):
        current_metadata.pop(annotation, None)
        if annotation in legacy_metadata:
            current_metadata[annotation] = legacy_metadata[annotation]
    # Pydantic leaves the (inlined, unreferenced) metadata model in $defs.
    assert current["$defs"].pop("RuleMetadata")
    assert legacy["$defs"].pop("ObjectMetadata")
    assert current == legacy


@pytest.mark.parametrize(
    ("value", "valid"), [(v, True) for v in REVIEWED] + [(v, False) for v in NOT_REVIEWED]
)
def test_reviewed_schema_and_model_agree(value: str, valid: bool, corpus: dict[str, Any]) -> None:
    body = _with_metadata(corpus["valid"]["rule::1.1"], reviewed=value)
    validator = Draft202012Validator(corpus["schemas"]["rule::1.1"], format_checker=_FORMATS)
    assert validator.is_valid(body) is valid
    try:
        load_object(body)
    except ValidationError:
        assert not valid
    else:
        assert valid


def test_reviewed_is_rejected_on_rule_1_0(corpus: dict[str, Any]) -> None:
    body = _with_metadata(corpus["valid"]["rule::1.0"], reviewed="2026-10-15")
    assert not Draft202012Validator(corpus["schemas"]["rule::1.0"]).is_valid(body)
    with pytest.raises(ValidationError):
        load_object(body)


def _signal_effort(objective: dict[str, Any], value: Any) -> dict[str, Any]:
    body = copy.deepcopy(objective)
    body["objective"]["signals"][0]["effort"] = value
    return body


def test_effort_schema_is_an_integer_without_string_vocabulary(corpus: dict[str, Any]) -> None:
    schema = corpus["schemas"]["objective::1.0"]
    effort = schema["$defs"]["DetectionSignal"]["properties"]["effort"]
    assert effort["anyOf"] == [{"type": "integer"}, {"type": "null"}]
    assert "enum" not in effort


@pytest.mark.parametrize(("value", "valid"), EFFORT)
def test_effort_schema_and_model_agree(value: Any, valid: bool, corpus: dict[str, Any]) -> None:
    body = _signal_effort(corpus["valid"]["objective::1.0"], value)
    assert Draft202012Validator(corpus["schemas"]["objective::1.0"]).is_valid(body) is valid
    try:
        load_object(body)
    except ValidationError:
        assert not valid
    else:
        assert valid
