"""Pydantic validation pipeline replacing Draft7Validator."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from opentide.loading.object_loader import (
    SchemaIdentifierError,
    SchemaMissingError,
    load_object_for_validation,
)
from opentide.models.base import TideModel
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.models.results import ValidationResult


def validate_object(
    model: TideModel,
    object_type: str,
    *,
    graph: Any = None,
) -> ValidationResult:
    """Re-validate a typed model against the revision its ``metadata.schema`` names."""
    if object_type not in CORE_OBJECT_TYPES:
        return ValidationResult(ok=False, errors=[f"Unknown object type {object_type!r}"])
    return _validate_body(model.model_dump(by_alias=True), object_type)


def validate_raw_payload(
    payload: dict[str, Any],
    object_type: str,
    *,
    graph: Any = None,
) -> ValidationResult:
    """Validate a raw YAML dict against the revision its ``metadata.schema`` names."""
    if object_type not in CORE_OBJECT_TYPES:
        return ValidationResult(ok=False, errors=[f"Unknown object type {object_type!r}"])
    return _validate_body(payload, object_type)


def _validate_body(body: dict[str, Any], object_type: str) -> ValidationResult:
    try:
        load_object_for_validation(body, object_type)
    except ValidationError as exc:
        return ValidationResult(
            ok=False, errors=[f"{err['loc']}: {err['msg']}" for err in exc.errors()]
        )
    except SchemaMissingError as exc:
        return ValidationResult(ok=False, errors=[f"{exc.code}: {exc}"])
    except SchemaIdentifierError as exc:
        return ValidationResult(ok=False, errors=[f"('metadata', 'schema'): {exc}"])
    return ValidationResult(ok=True)


def validate_all_objects(
    objects_index: dict[str, dict[str, dict[str, Any]]],
    *,
    scope: Any = None,
) -> dict[str, list[str]]:
    """Validate the objects in *objects_index*; return errors keyed by UUID.

    *objects_index* maps object type to ``{uuid: body}``, as
    ``Opentide.Index["objects"]`` does, and replaces the registry's objects for
    this run. Configuration and vocabularies come from the registry, and the
    checks that read the workspace (ID uniqueness, unreadable files) still read
    it.
    """
    if not any(registry for registry in objects_index.values()):
        return {}

    from opentide.core.registry import Opentide
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    index = {**Opentide.Index, "objects": objects_index}
    report = run_validation(scope=scope or ValidationScope.full(), index=index)
    return report.legacy_errors_by_uuid()
