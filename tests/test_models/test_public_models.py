"""``opentide.models``: the Rust classes under the names SDK code imports (UC-1.9, ADR 0011).

The package re-exports ``opentide._native.models``; the names it had that are
not Tide models keep working (the Pydantic machinery with a
``DeprecationWarning``); the helpers the Pydantic rule had as methods are
functions of ``opentide.models.delegation``; and importing it loads neither
Pydantic nor the Pydantic package the CLI runs on (``opentide._models``).
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest
import yaml

import opentide.models as models
from opentide._models.results import DeploymentResult, ValidationResult
from opentide._native import models as native
from opentide.models import delegation

ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "tests/fixtures/specifications/versioning/valid"

#: The modules whose Pydantic classes the Rust classes replace.
MODEL_MODULES = (
    "rule",
    "objective",
    "threat",
    "metadata",
    "platform",
    "platform_configs",
    "response",
)


def rule_document(revision: str = "1.1") -> dict[str, Any]:
    return yaml.safe_load((VALID / f"rule-{revision}.yaml").read_text(encoding="utf-8"))


def test_every_rust_class_is_exported_by_the_package_and_its_pydantic_module() -> None:
    classes = {
        name: value for name, value in vars(native).items() if hasattr(value, "__tide_fields__")
    }
    for name, cls in classes.items():
        assert getattr(models, name) is cls, name
    exported: dict[str, str] = {}
    for module_name in MODEL_MODULES:
        module = importlib.import_module(f"opentide.models.{module_name}")
        pydantic = importlib.import_module(f"opentide._models.{module_name}")
        for name in module.__all__:
            assert getattr(module, name) is classes[name], (module_name, name)
            # The Rust class stands where the Pydantic class of that name stood.
            assert hasattr(pydantic, name), (module_name, name)
            exported[name] = module_name
    assert set(exported) == set(classes)
    assert models.ValidationError is native.ValidationError
    assert set(models.__all__) >= set(classes) | {"ValidationError"}


def test_importing_the_package_loads_no_pydantic() -> None:
    script = (
        "import sys, json\n"
        "import opentide.models\n"
        "from opentide.models import DetectionRule, ThreatVector, DetectionObjective\n"
        "heavy = ('pydantic', 'yaml', 'opentide._models', 'opentide.core', 'opentide.loading')\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.split('.')[0] in heavy[:2]"
        " or m.startswith(heavy[2:]))))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == []


@pytest.mark.parametrize(
    ("name", "module"),
    [
        ("TideModel", "base"),
        ("TideField", "base"),
        ("field_json_schema_extra", "base"),
        ("TideRegistry", "rule"),
    ],
)
def test_the_pydantic_machinery_resolves_with_one_deprecation_warning(
    name: str, module: str
) -> None:
    script = (
        "import warnings\n"
        "warnings.simplefilter('always')\n"
        "with warnings.catch_warnings(record=True) as caught:\n"
        f"    from opentide.models import {name} as value\n"
        f"import opentide._models.{module} as source\n"
        f"assert value is source.{name}\n"
        "print(len(caught), caught[0].category.__name__, caught[0].message)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    count, category, message = result.stdout.split(" ", 2)
    assert (count, category) == ("1", "DeprecationWarning")
    assert f"opentide.models.{name} is part of the Pydantic models" in message


def test_a_model_module_forwards_its_other_names_with_a_warning() -> None:
    from opentide._models.platform import PLATFORM_CONFIG_MODELS

    platform = importlib.import_module("opentide.models.platform")
    with pytest.warns(DeprecationWarning, match="opentide.models.platform.PLATFORM_CONFIG_MODELS"):
        assert platform.PLATFORM_CONFIG_MODELS is PLATFORM_CONFIG_MODELS
    with pytest.raises(AttributeError, match="has no attribute 'Missing'"):
        platform.Missing  # noqa: B018 -- the lookup is the test


def test_the_names_that_are_not_tide_models_resolve_without_a_warning() -> None:
    from opentide._models import object_types

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert models.ValidationResult is ValidationResult
        assert models.DeploymentResult is DeploymentResult
        assert models.CORE_OBJECT_TYPES == object_types.CORE_OBJECT_TYPES
    with pytest.raises(AttributeError, match="has no attribute 'Missing'"):
        models.Missing  # noqa: B018 -- the lookup is the test


@pytest.mark.parametrize(
    "submodule",
    [
        "results",
        "configuration",
        "configuration.deployment",
        "deployment_enums",
        "object_types",
        "schema_registry",
    ],
)
def test_a_submodule_the_package_does_not_define_is_the_pydantic_packages(submodule: str) -> None:
    public = importlib.import_module(f"opentide.models.{submodule}")
    assert public is importlib.import_module(f"opentide._models.{submodule}")
    assert sys.modules[f"opentide.models.{submodule}"] is public


def test_a_submodule_neither_package_has_is_not_found() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("opentide.models.no_such_module")


@pytest.mark.parametrize(
    ("revision", "cls"),
    [("1.0", native.DetectionRule), ("1.1", native.DetectionRule_v1_1)],
)
def test_from_yaml_dict_picks_the_revision_and_sets_the_file(revision: str, cls: type) -> None:
    rule = delegation.from_yaml_dict(rule_document(revision), file=Path("rules/r.yaml"))
    assert type(rule) is cls
    assert rule.file == str(Path("rules/r.yaml"))
    assert delegation.from_yaml_dict(rule_document(revision)).file is None


def test_from_yaml_dict_refuses_a_missing_or_unknown_identifier() -> None:
    from opentide.loading.object_loader import SchemaIdentifierError, SchemaMissingError

    document = rule_document()
    with pytest.raises(SchemaMissingError):
        delegation.from_yaml_dict({**document, "metadata": {"uuid": "x"}})
    with pytest.raises(SchemaIdentifierError):
        delegation.from_yaml_dict(
            {**document, "metadata": {**document["metadata"], "schema": "rule::9.9"}}
        )
    with pytest.raises(models.ValidationError):
        delegation.from_yaml_dict({**document, "name": 1})


def test_to_pydantic_gives_the_same_object_as_a_pydantic_model() -> None:
    from opentide._models.rule import DetectionRule_v1_1

    rule = delegation.from_yaml_dict(rule_document(), file="rules/r.yaml")
    pydantic = delegation.to_pydantic(rule)
    assert type(pydantic) is DetectionRule_v1_1
    assert pydantic.file == Path("rules/r.yaml")
    assert pydantic.model_dump(mode="json", by_alias=True, exclude_none=True) == rule.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    block = delegation.to_pydantic(rule.configurations.sentinel)
    assert type(block).__module__ == "opentide._models.platform"
    with pytest.raises(TypeError, match="is not a Tide model"):
        delegation.to_pydantic(object())


class FakeRegistry:
    """The registry surface the Pydantic rule delegates to, recording each call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        deployer = type(
            "Deployer", (), {"deploy": lambda _, uuids, run: self.calls.append(("deploy", uuids))}
        )()
        self.Platforms = {"sentinel": type("Entry", (), {"deployer": deployer})()}

    def validate_rule(self, rule: Any) -> ValidationResult:
        self.calls.append(("validate", rule))
        return ValidationResult(ok=False, errors=["e"])

    def document_rule(self, rule: Any) -> str:
        return "unused: render_rule is preferred"

    def render_rule(self, rule: Any) -> str:
        self.calls.append(("render", rule))
        return f"# {rule.name}"

    def promote_rule(self, rule: Any, target_status: str) -> None:
        self.calls.append(("promote", target_status))


def test_the_delegation_helpers_hand_the_registry_the_rule_as_a_pydantic_model() -> None:
    from opentide._models.rule import DetectionRule as PydanticRule

    rule = delegation.from_yaml_dict(rule_document())
    registry = FakeRegistry()
    assert delegation.validate(rule, registry=registry) == ValidationResult(ok=False, errors=["e"])
    assert delegation.document(rule, registry=registry) == "# Sentinel KQL Rule"
    delegation.promote(rule, "PRODUCTION", registry=registry)
    result = delegation.deploy(rule, "sentinel", registry=registry, strategies=["PREVIEW"])
    assert result == DeploymentResult(
        platform="sentinel", uuids=[rule.metadata.uuid], dry_run=False
    )
    dry = delegation.deploy(rule, "sentinel", dry_run=True, registry=registry)
    assert dry.dry_run is True
    validated, rendered = registry.calls[0][1], registry.calls[1][1]
    assert isinstance(validated, PydanticRule) and isinstance(rendered, PydanticRule)
    assert validated.metadata.uuid == rule.metadata.uuid
    assert [call[0] for call in registry.calls] == ["validate", "render", "promote", "deploy"]
    assert registry.calls[2] == ("promote", "PRODUCTION")
    assert registry.calls[3] == ("deploy", [rule.metadata.uuid])
    report = delegation.validate_query(rule, "nowhere", registry=registry)
    assert report == ValidationResult(ok=False, errors=["Unknown platform 'nowhere'"])


def test_the_facade_renders_and_validates_a_rust_rule() -> None:
    from opentide._models.rule import DetectionRule as PydanticRule
    from opentide.core import registry as facade

    rule = delegation.from_yaml_dict(rule_document())
    converted = facade._pydantic_rule(rule)
    assert isinstance(converted, PydanticRule)
    assert converted.metadata.uuid == rule.metadata.uuid
    already = delegation.to_pydantic(rule)
    assert facade._pydantic_rule(already) is already  # ty: ignore[invalid-argument-type]  # a Pydantic rule
