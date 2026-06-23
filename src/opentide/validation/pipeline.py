"""Pydantic validation pipeline replacing Draft7Validator."""

from __future__ import annotations
from typing import Any
from pydantic import ValidationError
from opentide.models.base import TideModel
from opentide.models.objective import DetectionObjective
from opentide.models.results import ValidationResult
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector

_MODEL_BY_TYPE: dict[str, type[TideModel]] = {
    "mdr": DetectionRule,
    "dom": DetectionObjective,
    "tvm": ThreatVector,
}


def validate_object(model: TideModel, object_type: str) -> ValidationResult:
    """Re-validate a typed model instance (identity check via model_validate)."""
    cls = _MODEL_BY_TYPE.get(object_type)
    if cls is None:
        return ValidationResult(ok=False, errors=[f"Unknown object type {object_type!r}"])
    try:
        cls.model_validate(model.model_dump(by_alias=True))
        return ValidationResult(ok=True)
    except ValidationError as exc:
        return ValidationResult(
            ok=False, errors=[f"{err['loc']}: {err['msg']}" for err in exc.errors()]
        )


def validate_raw_payload(payload: dict[str, Any], object_type: str) -> ValidationResult:
    """Validate a raw YAML dict against the Pydantic model for its type."""
    cls = _MODEL_BY_TYPE.get(object_type)
    if cls is None:
        return ValidationResult(ok=False, errors=[f"Unknown object type {object_type!r}"])
    try:
        if object_type == "mdr":
            DetectionRule.from_yaml_dict(payload)
        elif object_type == "dom":
            DetectionObjective.from_yaml_dict(payload)
        else:
            ThreatVector.from_yaml_dict(payload)
        return ValidationResult(ok=True)
    except ValidationError as exc:
        return ValidationResult(
            ok=False, errors=[f"{err['loc']}: {err['msg']}" for err in exc.errors()]
        )


def validate_all_objects(
    objects_index: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, list[str]]:
    """Validate every object in an index bucket; return errors keyed by UUID."""
    errors: dict[str, list[str]] = {}
    for object_type, registry in objects_index.items():
        if object_type not in _MODEL_BY_TYPE:
            continue
        for uuid, body in registry.items():
            result = validate_raw_payload(body, object_type)
            if not result.ok:
                errors[uuid] = result.errors
    return errors
