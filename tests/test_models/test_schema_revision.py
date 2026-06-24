"""Schema revision routing, migration chains, and framework index."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import ConfigDict

from opentide.generation.router_schema import build_opentide_router
from opentide.loading.object_loader import load_object
from opentide.models.base import TideModel
from opentide.models.schema_registry import (
    get_chain,
    models_for_family,
    register_migration,
    register_model,
    reset_registry,
    resolve_model,
)
from opentide.models.version import SchemaVersion
from opentide.registry.artifacts import schema_artifact_name
from opentide.registry.builder import build_registry

_MODEL_CONFIG = ConfigDict(
    frozen=True,
    extra="ignore",
    populate_by_name=True,
    validate_assignment=True,
)


class ExampleV10(TideModel):
    __schema_identifier__: ClassVar[str] = "example::1.0"
    model_config = _MODEL_CONFIG

    name: str
    score: int = 0


class ExampleV11(TideModel):
    __schema_identifier__: ClassVar[str] = "example::1.1"
    model_config = _MODEL_CONFIG

    name: str
    score: int = 0
    label: str = ""


@pytest.fixture
def example_registry() -> None:
    reset_registry(shipped_only=True)
    register_model(ExampleV10)
    register_model(ExampleV11)
    register_migration(
        "example::1.0",
        "example::1.1",
        lambda data: {**data, "label": str(data.get("name", ""))},
    )
    yield
    reset_registry(shipped_only=True)


def test_registry_holds_multiple_versions_per_family(example_registry: None) -> None:
    models = models_for_family("example")
    assert set(models) == {"example::1.0", "example::1.1"}


def test_load_object_routes_by_metadata_schema(example_registry: None) -> None:
    body = {"name": "demo", "metadata": {"schema": "example::1.0"}}
    loaded = load_object(body)
    assert isinstance(loaded, ExampleV10)
    assert loaded.name == "demo"


def test_load_object_migrates_across_schema_revisions(example_registry: None) -> None:
    body = {"name": "migrated", "score": 2, "metadata": {"schema": "example::1.0"}}
    loaded = load_object(body, target_schema="example::1.1")
    assert isinstance(loaded, ExampleV11)
    assert loaded.label == "migrated"


def test_stamp_schema_identifier_updates_metadata() -> None:
    from opentide.models.migration import stamp_schema_identifier

    body = {"metadata": {"schema": "rule::1.0", "uuid": "x"}}
    stamped = stamp_schema_identifier(body, "rule::1.1")
    assert stamped["metadata"]["schema"] == "rule::1.1"


def test_schema_version_chain_supports_major_bump(example_registry: None) -> None:
    class ExampleV20(TideModel):
        __schema_identifier__: ClassVar[str] = "example::2.0"
        model_config = _MODEL_CONFIG
        name: str
        score: int = 0
        label: str = ""
        tier: str = ""

    register_model(ExampleV20)
    register_migration(
        "example::1.1",
        "example::2.0",
        lambda data: {**data, "tier": "gold"},
    )
    chain = get_chain("example")
    path = chain.path(
        SchemaVersion.parse("example::1.0"),
        SchemaVersion.parse("example::2.0"),
    )
    assert [version.as_identifier() for version in path] == [
        "example::1.0",
        "example::1.1",
        "example::2.0",
    ]
    body = {"name": "major", "metadata": {"schema": "example::1.0"}}
    loaded = load_object(body, target_schema="example::2.0")
    assert isinstance(loaded, ExampleV20)
    assert loaded.tier == "gold"


def test_unknown_schema_identifier_raises_lookup_error(example_registry: None) -> None:
    with pytest.raises(LookupError, match="unknown schema identifier"):
        resolve_model("rule::9.9")


def test_framework_schema_scan_indexes_disk_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    schema_dir = tmp_path / ".opentide" / "schemas"
    schema_dir.mkdir(parents=True)
    (schema_dir / "rule.1.0.schema.json").write_text(
        json.dumps(
            {
                "type": "object",
                "properties": {
                    "metadata": {
                        "properties": {"schema": {"const": "rule::1.0"}},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (schema_dir / "opentide.schema.json").write_text("{}", encoding="utf-8")

    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))
    index = build_registry()

    assert "rule::1.0" in index["framework_schemas"]
    assert index["framework_schemas"]["rule::1.0"].name == "rule.1.0.schema.json"
    rule_meta = index["json_schemas"]["rule::1.0"]["properties"]["metadata"]["properties"]
    assert rule_meta["schema"]["const"] == "rule::1.0"


def test_router_includes_registered_identifiers(example_registry: None) -> None:
    router = build_opentide_router()
    branches = router["oneOf"]
    consts = {
        branch["if"]["properties"]["metadata"]["properties"]["schema"]["const"]
        for branch in branches
    }
    assert "example::1.0" in consts
    assert "example::1.1" in consts
    assert any(
        branch["then"]["$ref"] == f"./{schema_artifact_name('example::1.1')}"
        for branch in branches
        if branch["if"]["properties"]["metadata"]["properties"]["schema"]["const"] == "example::1.1"
    )


def test_schema_version_chain_path(example_registry: None) -> None:
    chain = get_chain("example")
    path = chain.path(
        SchemaVersion.parse("example::1.0"),
        SchemaVersion.parse("example::1.1"),
    )
    assert [version.as_identifier() for version in path] == ["example::1.0", "example::1.1"]
