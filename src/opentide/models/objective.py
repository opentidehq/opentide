"""The Tide models of ``opentide.models.objective``: the Rust classes (ADR 0011).

Each class is the frozen Rust model of the same name (``opentide._native.models``).
"""

from __future__ import annotations

from opentide._native.models import (
    DetectionExample,
    DetectionObjective,
    DetectionSignal,
    ExternalDetector,
    ObjectiveBody,
    ObjectiveComposition,
    SignalData,
)

__all__ = [
    "DetectionExample",
    "DetectionObjective",
    "DetectionSignal",
    "ExternalDetector",
    "ObjectiveBody",
    "ObjectiveComposition",
    "SignalData",
]
