"""Schema identifier → Pydantic model registry (single source of truth)."""

from __future__ import annotations

from collections.abc import Collection
from typing import TYPE_CHECKING

from opentide.models.base import TideModel
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.models.version import MigrationFn, SchemaVersion, SchemaVersionChain

if TYPE_CHECKING:
    pass

SCHEMA_MODELS: dict[str, type[TideModel]] = {}
SCHEMA_CHAINS: dict[str, SchemaVersionChain] = {}
_BOOTSTRAPPED = False


def register_model(cls: type[TideModel]) -> type[TideModel]:
    """Register a Tide model under its ``__schema_identifier__``."""
    SCHEMA_MODELS[cls.schema_identifier()] = cls
    return cls


def unregister_model(schema_id: str) -> None:
    """Remove a schema registration (tests)."""
    SCHEMA_MODELS.pop(schema_id, None)


def is_registered(schema_id: str) -> bool:
    """Return whether a schema identifier has a registered model."""
    _ensure_bootstrapped()
    return schema_id in SCHEMA_MODELS


def resolve_model(schema_id: str) -> type[TideModel]:
    """Return Pydantic model class for a schema identifier."""
    _ensure_bootstrapped()
    if schema_id not in SCHEMA_MODELS:
        raise LookupError(f"unknown schema identifier: {schema_id!r}")
    return SCHEMA_MODELS[schema_id]


def registered_identifiers() -> list[str]:
    """All registered schema identifiers."""
    _ensure_bootstrapped()
    return sorted(SCHEMA_MODELS.keys())


def identifiers_for_families(families: Collection[str]) -> list[str]:
    """Registered identifiers whose family is in *families*."""
    result: list[str] = []
    for schema_id in registered_identifiers():
        if SchemaVersion.parse(schema_id).family in families:
            result.append(schema_id)
    return result


def models_for_family(family: str) -> dict[str, type[TideModel]]:
    """All registered models for a schema family, keyed by full identifier."""
    family = family.lower()
    return {
        schema_id: model
        for schema_id, model in SCHEMA_MODELS.items()
        if SchemaVersion.parse(schema_id).family == family
    }


def latest_identifier(family: str) -> str:
    """Highest registered schema identifier for a family."""
    models = models_for_family(family)
    if not models:
        raise LookupError(f"no registered schema for family {family!r}")
    return max(models.keys(), key=lambda item: SchemaVersion.parse(item).sort_key())


def latest_model_for_family(family: str) -> type[TideModel]:
    """Latest registered model class for a schema family."""
    return resolve_model(latest_identifier(family))


def core_object_schemas() -> dict[str, type[TideModel]]:
    """Latest registered model per core object folder type."""
    _ensure_bootstrapped()
    return {family: latest_model_for_family(family) for family in CORE_OBJECT_TYPES}


def get_chain(family: str) -> SchemaVersionChain:
    """Return (or create) the migration chain for a schema family."""
    key = family.lower()
    if key not in SCHEMA_CHAINS:
        SCHEMA_CHAINS[key] = SchemaVersionChain(key)
    return SCHEMA_CHAINS[key]


def register_migration(
    source: SchemaVersion | str,
    target: SchemaVersion | str,
    fn: MigrationFn,
) -> None:
    """Register a single-step migration on a family's chain."""
    source_v = source if isinstance(source, SchemaVersion) else SchemaVersion.parse(source)
    target_v = target if isinstance(target, SchemaVersion) else SchemaVersion.parse(target)
    get_chain(source_v.family).register(source_v, target_v, fn)


def reset_registry(*, shipped_only: bool = True) -> None:
    """Clear registry state (tests). Re-bootstrap shipped models when requested."""
    global _BOOTSTRAPPED
    SCHEMA_MODELS.clear()
    SCHEMA_CHAINS.clear()
    _BOOTSTRAPPED = False
    if shipped_only:
        _bootstrap()


def _ensure_bootstrapped() -> None:
    if not _BOOTSTRAPPED:
        _bootstrap()


def _bootstrap() -> None:
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    from opentide.models.objective import DetectionObjective
    from opentide.models.rule import DetectionRule
    from opentide.models.threat import ThreatVector
    from opentide.models.visibility import VisibilityConfig

    for model_cls in (DetectionRule, ThreatVector, DetectionObjective, VisibilityConfig):
        register_model(model_cls)
    _BOOTSTRAPPED = True


# Eager bootstrap on import so production callers see shipped models immediately.
_bootstrap()
