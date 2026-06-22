"""Detection rule loading — replaces ObjectLoader / PlatformConfigLoader."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

from opentide.models.metadata import ObjectReferences
from opentide.models.platform import RuleConfigurations, parse_platform_config
from opentide.models.rule import DetectionRule


def _load_response(response_config: dict[str, Any]) -> dict[str, Any]:
    """Normalise response block for Pydantic validation."""
    return dict(response_config)


def _load_configurations(system_configurations: dict[str, Any]) -> RuleConfigurations:
    """Parse per-platform configuration blocks into RuleConfigurations."""
    kwargs: dict[str, Any] = {}
    for key, value in system_configurations.items():
        if value and key in RuleConfigurations.model_fields:
            kwargs[key] = parse_platform_config(key, value)
    return cast(RuleConfigurations, RuleConfigurations.model_validate(kwargs))


def load_rule_from_dict(
    mdr: dict[str, Any],
    *,
    file: Path | None = None,
) -> DetectionRule:
    """Convert a raw MDR mapping into a typed DetectionRule."""
    payload = deepcopy(mdr)
    metadata_raw = payload.pop("metadata", {})
    references_raw = payload.pop("references", None)
    response_raw = payload.pop("response", None)
    configurations_raw = payload.pop("configurations", {})

    if references_raw is not None:
        references_raw = ObjectReferences.coerce_public_keys(references_raw)

    rule_data: dict[str, Any] = {
        **payload,
        "metadata": metadata_raw,
        "references": references_raw,
        "response": _load_response(response_raw) if response_raw else None,
        "configurations": (
            _load_configurations(configurations_raw).model_dump(exclude_none=True)
            if configurations_raw
            else None
        ),
    }

    rule = DetectionRule.from_yaml_dict(rule_data, file=file)
    return rule


def load_rule_compat(mdr: dict[str, Any]) -> Any:
    """Load rule using legacy dataclass path when full platform nesting is required."""
    import sys

    from opentide.core.root import repository_root

    root = str(repository_root())
    if root not in sys.path:
        sys.path.append(root)
    from Engines.modules.loaders.object_loader import ObjectLoader

    return ObjectLoader.load_rule(deepcopy(mdr))
