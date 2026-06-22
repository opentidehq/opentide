"""Detection objective (DOM) loading — Pydantic-only signal/objective parsing."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

from opentide.models.objective import DetectionObjective, DetectionSignal


def load_signal_from_dict(signal: dict[str, Any]) -> DetectionSignal:
    """Convert a raw signal mapping into a typed DetectionSignal."""
    return cast(DetectionSignal, DetectionSignal.model_validate(deepcopy(signal)))


def load_objective_from_dict(dom: dict[str, Any]) -> DetectionObjective:
    """Convert a raw detection objective mapping into a typed DetectionObjective."""
    return DetectionObjective.from_yaml_dict(deepcopy(dom))
