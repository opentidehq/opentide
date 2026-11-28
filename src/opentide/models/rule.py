"""The Tide models of ``opentide.models.rule``: the Rust classes (ADR 0011).

Each class is the frozen Rust model of the same name (``opentide._native.models``).
"""

from __future__ import annotations

from opentide._native.models import (
    DetectionRule,
    DetectionRule_v1_1,
)

__all__ = [
    "DetectionRule",
    "DetectionRule_v1_1",
]
