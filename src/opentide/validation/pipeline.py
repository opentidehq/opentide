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
    "rule": DetectionRule,
    "objective": DetectionObjective,
    "threat": ThreatVector,
}


def validate_object(
    model: TideModel,
    object_type: str,
    *,
    graph: Any = None,
) -> ValidationResult:
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


def validate_raw_payload(
    payload: dict[str, Any],
    object_type: str,
    *,
    graph: Any = None,
) -> ValidationResult:
    """Validate a raw YAML dict against the Pydantic model for its type."""
    cls = _MODEL_BY_TYPE.get(object_type)
    if cls is None:
        return ValidationResult(ok=False, errors=[f"Unknown object type {object_type!r}"])
    try:
        if object_type == "rule":
            DetectionRule.from_yaml_dict(payload)
        elif object_type == "objective":
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
    *,
    scope: Any = None,
) -> dict[str, list[str]]:
    """Validate every object in an index bucket; return errors keyed by UUID."""
    if not any(registry for registry in objects_index.values()):
        return {}

    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    report = run_validation(scope=scope or ValidationScope.full())
    return report.legacy_errors_by_uuid()
