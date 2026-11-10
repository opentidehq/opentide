"""The Rust models (``opentide._native.models``, UC-1.9) against the Pydantic ones.

The Pydantic models in ``opentide.models`` are the oracle (ADR 0011): every
Rust class carries a Pydantic class's name, fields and serialised names; every
object file of the fixtures reads to the same values; and every case of the
schema crate's oracle tables that has no recorded difference reports the same
errors, with the same type, location and message. Behaviour that is the Rust
class's own (frozen, hashing, pickling, copies) is in
``crates/opentide-schema/tests/python_models.rs``.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pickle
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from opentide._native import models as native
from opentide.core.io import load_toml, stringify_yaml_temporals
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule, DetectionRule_v1_1
from opentide.models.threat import ThreatVector

ROOT = Path(__file__).resolve().parents[2]
ORACLE_TABLES = ROOT / "crates/opentide-schema/tests/oracle"
STUB = ROOT / "src/opentide/_native/models.pyi"

#: The modules whose Pydantic models the Rust classes stand for.
PYDANTIC_MODULES = (
    "rule",
    "objective",
    "threat",
    "metadata",
    "platform",
    "platform_configs",
    "response",
)
#: Pydantic models with no Rust class: the abstract bases, and the result
#: models, which are not Tide models.
WITHOUT_RUST_CLASS = frozenset(
    {"TideModel", "PlatformConfigBase", "ValidationResult", "DeploymentResult"}
)

PYDANTIC: dict[str, type[BaseModel]] = {
    "rule::1.0": DetectionRule,
    "rule::1.1": DetectionRule_v1_1,
    "objective::1.0": DetectionObjective,
    "threat::1.0": ThreatVector,
}
RUST: dict[str, Any] = {
    "rule::1.0": native.DetectionRule,
    "rule::1.1": native.DetectionRule_v1_1,
    "objective::1.0": native.DetectionObjective,
    "threat::1.0": native.ThreatVector,
}
DUMPS: tuple[dict[str, bool], ...] = (
    {},
    {"by_alias": True},
    {"exclude_none": True},
    {"by_alias": True, "exclude_none": True},
)


def pydantic_models() -> dict[str, type[BaseModel]]:
    found: dict[str, type[BaseModel]] = {}
    for name in PYDANTIC_MODULES:
        module = importlib.import_module(f"opentide.models.{name}")
        for attribute, value in vars(module).items():
            if inspect.isclass(value) and issubclass(value, BaseModel) and value is not BaseModel:
                found.setdefault(attribute, value)
    return found


def rust_classes() -> dict[str, Any]:
    return {
        name: value for name, value in vars(native).items() if hasattr(value, "__tide_fields__")
    }


def object_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted((ROOT / "tests/fixtures").rglob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            continue
        metadata = document.get("metadata") if isinstance(document, dict) else None
        if isinstance(metadata, dict) and metadata.get("schema") in PYDANTIC:
            files.append(path)
    return files


def oracle_cases() -> list[Any]:
    """Each case without a recorded difference that a model reads: one PyYAML
    parses and whose ``metadata.schema`` names a revision (the others are
    refused before a model runs)."""
    cases: list[Any] = []
    for table in ("objects_cases.toml", "platform_cases.toml"):
        for case in load_toml(ORACLE_TABLES / table)["case"]:
            if "difference" in case:
                continue
            try:
                document = yaml.safe_load(case["yaml"])
            except yaml.YAMLError:
                continue
            metadata = document.get("metadata") if isinstance(document, dict) else None
            schema = metadata.get("schema") if isinstance(metadata, dict) else None
            if schema in PYDANTIC:
                cases.append(pytest.param(schema, document, id=case["id"]))
    return cases


def test_every_tide_model_has_a_rust_class_with_its_fields() -> None:
    pydantic = pydantic_models()
    rust = rust_classes()
    assert set(pydantic) - set(rust) == WITHOUT_RUST_CLASS
    assert set(rust) <= set(pydantic)
    for name, cls in rust.items():
        model = pydantic[name]
        assert cls.__name__ == name
        assert cls.__module__ == "opentide._native.models"
        assert [attribute for attribute, _ in cls.__tide_fields__] == list(model.model_fields), name
        assert [serialised for _, serialised in cls.__tide_fields__] == [
            field.alias or attribute for attribute, field in model.model_fields.items()
        ], name
        identifier = getattr(model, "__schema_identifier__", None)
        assert getattr(cls, "__schema_identifier__", None) == identifier, name
        # A serialised name that is not the attribute's reads it (`.schema`),
        # as a declared attribute, not through a catch-all `__getattr__`.
        for attribute, serialised in cls.__tide_fields__:
            if attribute != serialised:
                descriptor = inspect.getattr_static(cls, serialised)
                assert type(descriptor).__name__ == "getset_descriptor", (name, serialised)
        assert "__getattr__" not in vars(cls), name


@pytest.mark.parametrize("path", object_files(), ids=lambda path: path.relative_to(ROOT).as_posix())
def test_every_fixture_object_reads_as_the_pydantic_model_does(path: Path) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    schema = document["metadata"]["schema"]
    try:
        expected = PYDANTIC[schema].model_validate(stringify_yaml_temporals(document))
    except PydanticValidationError:
        with pytest.raises(native.ValidationError):
            RUST[schema].model_validate(document)
        return
    actual = RUST[schema].model_validate(document)
    for options in DUMPS:
        assert actual.model_dump(**options) == expected.model_dump(**options), options
    # Field by field, in order, mappings in the document's order.
    assert repr(actual) == repr(expected)
    if isinstance(expected, DetectionRule):
        for helper in ("platform_statuses", "displayed_severity", "alert_severity"):
            assert getattr(actual, helper) == getattr(expected, helper), helper
        assert list(actual.platform_statuses) == list(expected.platform_statuses)
    # Read from the Pydantic model, it is the same value.
    assert RUST[schema].model_validate(expected) == actual
    assert pickle.loads(pickle.dumps(actual)) == actual


@pytest.mark.parametrize(("schema", "document"), oracle_cases())
def test_every_oracle_case_reports_the_pydantic_errors(schema: str, document: Any) -> None:
    expected_errors, actual_errors = both_errors(schema, document)
    expected = [(item["type"], tuple(item["loc"]), item["msg"]) for item in expected_errors]
    actual = [(item["type"], tuple(item["loc"]), item["msg"]) for item in actual_errors]
    assert actual == expected
    for rust, pydantic in zip(actual_errors, expected_errors, strict=True):
        assert recorded_extras(rust) == expected_extras(rust, pydantic)


def both_errors(schema: str, document: Any) -> tuple[list[Any], list[Any]]:
    """Pydantic's ``errors()`` and the Rust class's, for *document*."""
    try:
        PYDANTIC[schema].model_validate(stringify_yaml_temporals(document))
        expected: list[Any] = []
    except PydanticValidationError as error:
        expected = list(error.errors())
    try:
        RUST[schema].model_validate(document)
        actual: list[Any] = []
    except native.ValidationError as error:
        actual = error.errors()  # ty: ignore[unresolved-attribute]  # set on each instance
    return expected, actual


def recorded_extras(rust: dict[str, Any]) -> dict[str, Any]:
    return {key: rust[key] for key in ("input", "ctx") if key in rust}


def expected_extras(rust: dict[str, Any], pydantic: dict[str, Any]) -> dict[str, Any]:
    """What the Rust error holds of Pydantic's ``input`` and ``ctx``: the
    input when it is a string, and every context value as ``str()`` gives it."""
    extras: dict[str, Any] = {}
    if isinstance(pydantic.get("input"), str):
        extras["input"] = pydantic["input"]
    if pydantic.get("ctx"):
        extras["ctx"] = {key: str(value) for key, value in pydantic["ctx"].items()}
    return extras


def test_the_oracle_cases_compare_inputs_and_contexts() -> None:
    """The comparison above is not vacuous: oracle cases record both."""
    seen = {"input": 0, "ctx": 0}
    for case in oracle_cases():
        schema, document = case.values
        _, actual_errors = both_errors(schema, document)
        for rust in actual_errors:
            for key in seen:
                seen[key] += key in rust
    assert seen["input"] >= 10 and seen["ctx"] >= 10, seen


def test_the_generated_stub_declares_every_class() -> None:
    tree = ast.parse(STUB.read_text(encoding="utf-8"))
    declared = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert declared == set(rust_classes())
    # The stub is complete: no `__getattr__`, on the module or a class, that
    # would type a misspelt attribute or a missing name as `Any`.
    assert not [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "__getattr__"
    ]
    # ValidationError is a `create_exception!` type, which PyO3's introspection
    # cannot describe as a class: the module exports it as a value whose type
    # the stub declares.
    annotations = {
        node.target.id: ast.unparse(node.annotation)
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert annotations == {"ValidationError": "Final[type[ValueError]]"}
    assert issubclass(native.ValidationError, ValueError)
    [dunder_all] = [
        statement.value
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and [ast.unparse(target) for target in statement.targets] == ["__all__"]
    ]
    assert set(ast.literal_eval(dunder_all)) == set(rust_classes()) | {"ValidationError"}
