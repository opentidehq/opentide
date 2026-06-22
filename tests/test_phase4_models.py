"""Phase 4 foundation — TideModel, SchemaVersion, EnumRegistry unit tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import Field
from pydantic.fields import FieldInfo

from opentide.models.base import TideField, TideModel, field_json_schema_extra
from opentide.models.enums import EnumEntry, EnumRegistry
from opentide.models.metadata import ObjectMetadata, ObjectReferences, Organisation
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector
from opentide.models.version import SchemaVersion, SchemaVersionChain

INVENTORY = Path(__file__).resolve().parents[1] / "docs/migration/behaviour-inventory.md"


def _metadata() -> dict[str, Any]:
    return {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "rule::1.0",
        "version": 1,
        "created": "2026-01-01",
        "modified": "2026-01-02",
        "tlp": "clear",
    }


def test_behaviour_inventory_committed() -> None:
    assert INVENTORY.is_file()
    text = INVENTORY.read_text()
    assert "JS-01" in text
    assert "TP-01" in text


def test_tide_field_attaches_schema_extra() -> None:
    field = TideField("x", schema_extra={"tide.vocab": True})
    assert isinstance(field, FieldInfo)


class _ExampleModel(TideModel):
    __schema_identifier__ = "example::1.0"
    name: str


def test_tide_model_schema_identifier() -> None:
    assert _ExampleModel.schema_identifier() == "example::1.0"


def test_field_json_schema_extra_reads_metadata() -> None:
    class M(TideModel):
        label: str = Field(json_schema_extra={"tide.template.hide": True})

    info = M.model_fields["label"]
    assert field_json_schema_extra(info)["tide.template.hide"] is True


def test_schema_version_parse() -> None:
    version = SchemaVersion.parse("rule::1.0")
    assert version.family == "rule"
    assert version.major == 1
    assert version.minor == 0
    assert version.as_identifier() == "rule::1.0"


def test_schema_version_from_version_string_minor() -> None:
    version = SchemaVersion.from_version_string("objective", "2.3")
    assert version.major == 2
    assert version.minor == 3
    assert version.as_identifier() == "objective::2.3"


def test_schema_version_sort_key() -> None:
    left = SchemaVersion.parse("rule::1.0")
    right = SchemaVersion.parse("rule::1.1")
    assert left.sort_key() < right.sort_key()


def test_schema_version_chain_migrate() -> None:
    chain = SchemaVersionChain("rule")

    def bump(data: dict[str, object]) -> dict[str, object]:
        copy = dict(data)
        copy["version"] = 2
        return copy

    source = SchemaVersion.parse("rule::1.0")
    target = SchemaVersion.parse("rule::1.1")
    chain.register(source, target, bump)
    result = chain.migrate({"version": 1}, source, target)
    assert result["version"] == 2


def test_schema_version_chain_path() -> None:
    chain = SchemaVersionChain("rule")
    source = SchemaVersion.parse("rule::1.0")
    target = SchemaVersion.parse("rule::1.2")
    path = chain.path(source, target)
    assert path[0].as_identifier() == "rule::1.0"
    assert path[-1].as_identifier() == "rule::1.2"


def test_enum_entry_validate_lengths_ok() -> None:
    EnumEntry(values=["a"], descriptions=["A"]).validate_lengths()


def test_enum_entry_validate_lengths_mismatch() -> None:
    with pytest.raises(ValueError):
        EnumEntry(values=["a"], descriptions=["A", "B"]).validate_lengths()


def test_enum_registry_register_and_resolve() -> None:
    registry = EnumRegistry()
    registry.register("severity", ["High", "Low"], ["High severity", "Low severity"])
    values, descriptions = registry.resolve("severity")
    assert values == ["High", "Low"]
    assert descriptions == ["High severity", "Low severity"]


def test_enum_registry_resolve_missing() -> None:
    registry = EnumRegistry()
    assert registry.resolve("missing") == ([""], [""])


def test_enum_registry_clear_and_vocabularies() -> None:
    registry = EnumRegistry()
    registry.register("impact", ["A"], ["A"])
    assert registry.vocabularies() == frozenset({"impact"})
    registry.clear()
    assert registry.vocabularies() == frozenset()


def test_object_references_coerce_public_keys() -> None:
    data = ObjectReferences.coerce_public_keys({"public": {"1": "ref"}})
    refs = ObjectReferences.model_validate(data)
    assert refs.public == {1: "ref"}


def test_organisation_model() -> None:
    org = Organisation(uuid="u", name="Org")
    assert org.name == "Org"


def test_detection_rule_from_yaml_and_delegation() -> None:
    payload = {
        "name": "Test rule",
        "metadata": _metadata(),
        "description": "desc",
        "status": "STAGING",
        "severity": "High",
        "techniques": ["T1059"],
        "platforms": {},
    }
    rule = DetectionRule.from_yaml_dict(payload, file=Path("rule.yaml"))
    assert rule.file == Path("rule.yaml")
    assert rule.metadata.schema_id == "rule::1.0"

    registry = MagicMock()
    registry.Platforms = {"sentinel": MagicMock(deployer=MagicMock())}
    registry.validate_rule.return_value = MagicMock(ok=True, errors=[], warnings=[])
    registry.document_rule.return_value = "# doc"

    bound = rule.bind_registry(registry)
    bound.deploy("sentinel", dry_run=True)
    bound.validate()
    bound.document()
    bound.promote("PRODUCTION")

    result = bound.validate_query("crowdstrike")
    assert result.ok is False


def test_detection_rule_requires_registry() -> None:
    rule = DetectionRule(
        name="R",
        metadata=ObjectMetadata.model_validate(_metadata()),
        description="d",
    )
    with pytest.raises(RuntimeError):
        rule.deploy("sentinel")


def test_threat_vector_from_yaml_dict() -> None:
    payload = {
        "name": "TVM",
        "criticality": "High",
        "metadata": {**_metadata(), "schema": "threat::1.0"},
        "threat": {
            "description": "d",
            "severity": "High",
            "impact": "Data Breach",
            "leverage": "High",
            "viability": "High",
            "terrain": "Endpoint",
            "att&ck": ["T1059"],
        },
    }
    tvm = ThreatVector.from_yaml_dict(payload)
    assert ThreatVector.schema_identifier() == "threat::1.0"
    assert tvm.threat.att_ck == ["T1059"]


def test_detection_objective_from_yaml_dict() -> None:
    payload = {
        "name": "Objective",
        "metadata": {**_metadata(), "schema": "objective::1.0"},
        "composition": {"strategy": "synergetic", "description": "compose"},
        "objective": {
            "priority": "High",
            "type": "Threat",
            "description": "obj",
            "composition": {"strategy": "synergetic", "description": "compose"},
            "signals": [
                {
                    "name": "Signal",
                    "uuid": "00000000-0000-4000-8000-000000000099",
                    "description": "sig",
                    "severity": "Medium",
                    "methodology": "analytics",
                    "entities": ["host"],
                    "data": {"availability": "Complete", "requirements": "logs"},
                }
            ],
        },
    }
    dom = DetectionObjective.from_yaml_dict(payload)
    assert DetectionObjective.schema_identifier() == "objective::1.0"
    assert len(dom.objective.signals) == 1
