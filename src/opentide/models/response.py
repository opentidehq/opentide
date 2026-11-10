"""The Tide models of ``opentide.models.response``: the Rust classes (ADR 0011).

Each class is the frozen Rust model of the same name (``opentide._native.models``).
The module's other names, which are the Pydantic package's (``opentide._models.response``),
still resolve, with a ``DeprecationWarning``, for one minor release.
"""

from __future__ import annotations

from opentide._native.models import (
    ResponseProcedure,
    ResponseSearch,
    RuleResponse,
)
from opentide.models._compat import deprecated_attribute

__all__ = [
    "ResponseProcedure",
    "ResponseSearch",
    "RuleResponse",
]


def __getattr__(name: str) -> object:
    return deprecated_attribute(__name__, "opentide._models.response", name)
