"""The Tide models of ``opentide.models.threat``: the Rust classes (ADR 0011).

Each class is the frozen Rust model of the same name (``opentide._native.models``).
"""

from __future__ import annotations

from opentide._native.models import (
    ThreatActor,
    ThreatBody,
    ThreatVector,
)

__all__ = [
    "ThreatActor",
    "ThreatBody",
    "ThreatVector",
]
