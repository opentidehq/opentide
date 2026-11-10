"""The helpers the Pydantic models had as methods, for the Rust models (ADR 0011).

A Rust class is frozen and cannot be subclassed, so what the Pydantic rule did
through its bound registry (``rule.validate()``, ``rule.deploy("sentinel")``,
``rule.document()``, …) is a function here that takes the Rust model. Each one
is thin: it hands the CLI's code, which still runs on the Pydantic models
(``opentide._models``), the same object as a Pydantic model
(:func:`to_pydantic`), and returns what that code returns.

>>> from opentide.models.delegation import from_yaml_dict, validate
>>> rule = from_yaml_dict(document)          # a Rust DetectionRule
>>> validate(rule).ok                        # was rule.validate().ok
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, TypeAlias, Union

from opentide._native.models import (
    DetectionObjective,
    DetectionRule,
    DetectionRule_v1_1,
    ThreatVector,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from opentide._models.base import TideModel
    from opentide._models.results import DeploymentResult, ValidationResult
    from opentide._models.rule import DetectionRule as PydanticRule
    from opentide._models.rule import TideRegistry
    from opentide.query.service import QueryRun

#: A Tide object as a Rust model.
TideObject: TypeAlias = Union[DetectionRule, DetectionRule_v1_1, DetectionObjective, ThreatVector]  # noqa: UP007 -- a runtime alias on Python 3.10
#: A detection rule as a Rust model, either revision.
Rule: TypeAlias = Union[DetectionRule, DetectionRule_v1_1]  # noqa: UP007 -- a runtime alias on Python 3.10

#: Each object revision's Rust class, by ``metadata.schema``.
REVISIONS: dict[str, type[TideObject]] = {
    "rule::1.0": DetectionRule,
    "rule::1.1": DetectionRule_v1_1,
    "objective::1.0": DetectionObjective,
    "threat::1.0": ThreatVector,
}

#: The Pydantic modules that hold a class of each Rust class's name.
_PYDANTIC_MODULES = (
    "rule",
    "objective",
    "threat",
    "metadata",
    "platform",
    "platform_configs",
    "response",
)


def from_yaml_dict(
    payload: Mapping[str, Any], *, file: str | os.PathLike[str] | None = None
) -> TideObject:
    """The Rust model of a loaded Tide document, the class chosen by its
    ``metadata.schema``; *file* sets a rule's ``file``.

    As the Pydantic loaders do, a missing identifier raises
    ``SchemaMissingError`` (a ``ValueError``) and an unknown one
    ``SchemaIdentifierError`` (a ``LookupError``), both from
    ``opentide.loading.object_loader``; a document that does not fit raises
    ``opentide.models.ValidationError``.
    """
    metadata = payload.get("metadata")
    schema = metadata.get("schema") if isinstance(metadata, Mapping) else None
    if not schema:
        from opentide.loading.object_loader import SchemaMissingError

        raise SchemaMissingError("The object has no metadata.schema")
    cls = REVISIONS.get(str(schema))
    if cls is None:
        from opentide.loading.object_loader import SchemaIdentifierError

        raise SchemaIdentifierError(f"Unknown schema identifier {schema!r}")
    document = dict(payload)
    if file is not None and cls in (DetectionRule, DetectionRule_v1_1):
        document["file"] = os.fspath(file)
    return cls.model_validate(document)


def to_pydantic(model: Any) -> TideModel:
    """*model*, a Rust model, as the Pydantic model of the same name that the
    CLI's code reads (a rule keeps its ``file``)."""
    import importlib
    from pathlib import Path

    name = type(model).__name__
    for module_name in _PYDANTIC_MODULES:
        module = importlib.import_module(f"opentide._models.{module_name}")
        cls = getattr(module, name, None)
        if cls is not None:
            break
    else:
        raise TypeError(f"{name} is not a Tide model")
    document = model.model_dump(by_alias=True, exclude_none=True)
    if isinstance(model, (DetectionRule, DetectionRule_v1_1)):
        document.pop("file", None)
        file = Path(model.file) if model.file is not None else None
        return cls.from_yaml_dict(document, file=file)
    return cls.model_validate(document)


def _bound(rule: Rule, registry: TideRegistry | None) -> PydanticRule:
    if registry is None:
        from opentide.core.registry import Opentide

        registry = Opentide
    pydantic: PydanticRule = to_pydantic(rule)  # ty: ignore[invalid-assignment]  # a rule's Pydantic model is a DetectionRule
    return pydantic.bind_registry(registry)


def validate(rule: Rule, *, registry: TideRegistry | None = None) -> ValidationResult:
    """Schema and cross-object checks of *rule* (was ``rule.validate()``);
    *registry* defaults to ``opentide.Opentide``."""
    return _bound(rule, registry).validate()


def validate_query(
    rule: Rule, platform: str, *, registry: TideRegistry | None = None
) -> ValidationResult:
    """The query syntax of *rule*'s *platform* block (was ``rule.validate_query(platform)``)."""
    return _bound(rule, registry).validate_query(platform)


def run_query(
    rule: Rule,
    platform: str,
    *,
    tenants: Sequence[str] = (),
    since: str | None = None,
    limit: int | None = None,
) -> QueryRun:
    """The rows *rule*'s *platform* query returns from the tenants, read-only
    (was ``rule.run_query(...)``); *limit* defaults to the query default."""
    from opentide.query.models import DEFAULT_LIMIT

    pydantic: PydanticRule = to_pydantic(rule)  # ty: ignore[invalid-assignment]  # a rule's Pydantic model is a DetectionRule
    return pydantic.run_query(
        platform,
        tenants=tenants,
        since=since,
        limit=DEFAULT_LIMIT if limit is None else limit,
    )


def deploy(
    rule: Rule,
    platform: str,
    dry_run: bool = False,
    *,
    strategies: Iterable[str] | None = None,
    registry: TideRegistry | None = None,
) -> DeploymentResult:
    """Deploys *rule* to *platform* (was ``rule.deploy(platform, ...)``)."""
    return _bound(rule, registry).deploy(platform, dry_run, strategies=strategies)


def document(rule: Rule, *, registry: TideRegistry | None = None) -> str:
    """*rule*'s documentation page (was ``rule.document()``)."""
    return _bound(rule, registry).document()


def promote(rule: Rule, target_status: str, *, registry: TideRegistry | None = None) -> None:
    """Promotes *rule* (was ``rule.promote(status)``)."""
    _bound(rule, registry).promote(target_status)


__all__ = [
    "REVISIONS",
    "Rule",
    "TideObject",
    "deploy",
    "document",
    "from_yaml_dict",
    "promote",
    "run_query",
    "to_pydantic",
    "validate",
    "validate_query",
]
