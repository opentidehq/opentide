"""Detection rule loading — Pydantic-only rule parsing."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

from opentide.loading.platform_loader import load_platform_config
from opentide.models.metadata import ObjectReferences
from opentide.models.platform import PLATFORM_CONFIG_MODELS, RuleConfigurations
from opentide.models.response import ResponseProcedure, ResponseSearch, RuleResponse
from opentide.models.rule import DetectionRule


def _load_response(response_config: dict[str, Any]) -> RuleResponse:
    """Normalise response block for Pydantic validation."""
    payload = deepcopy(response_config)
    procedure_raw = payload.pop("procedure", None)
    procedure = None
    if procedure_raw:
        searches_raw = procedure_raw.pop("searches", None)
        searches = (
            [ResponseSearch.model_validate(search) for search in searches_raw]
            if searches_raw
            else None
        )
        procedure = ResponseProcedure(**procedure_raw, searches=searches)
    return RuleResponse(**payload, procedure=procedure)


def _load_configurations(system_configurations: dict[str, Any]) -> RuleConfigurations:
    """Parse per-platform configuration blocks into RuleConfigurations."""
    kwargs: dict[str, Any] = {}
    for key, value in system_configurations.items():
        if value and key in PLATFORM_CONFIG_MODELS:
            kwargs[key] = load_platform_config(key, value)
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
            _load_configurations(configurations_raw) if configurations_raw else None
        ),
    }

    rule = DetectionRule.from_yaml_dict(rule_data, file=file)
    return rule
