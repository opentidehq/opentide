"""The Tide models of ``opentide.models.threat``: the Rust classes (ADR 0011).

Each class is the frozen Rust model of the same name (``opentide._native.models``).
The module's other names, which are the Pydantic package's (``opentide._models.threat``),
still resolve, with a ``DeprecationWarning``, for one minor release.
"""

from __future__ import annotations

from opentide._native.models import (
    ThreatActor,
    ThreatBody,
    ThreatVector,
)
from opentide.models._compat import deprecated_attribute

__all__ = [
    "ThreatActor",
    "ThreatBody",
    "ThreatVector",
]


def __getattr__(name: str) -> object:
    return deprecated_attribute(__name__, "opentide._models.threat", name)
