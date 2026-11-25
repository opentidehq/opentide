"""The Tide models of ``opentide.models.metadata``: the Rust classes (ADR 0011).

Each class is the frozen Rust model of the same name (``opentide._native.models``).
"""

from __future__ import annotations

from opentide._native.models import (
    ObjectMetadata,
    ObjectReferences,
    Organisation,
    RuleMetadata,
)

__all__ = [
    "ObjectMetadata",
    "ObjectReferences",
    "Organisation",
    "RuleMetadata",
]
