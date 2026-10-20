"""opentide DetectionOps engine."""

from __future__ import annotations

from opentide._version import __version__
from opentide.core.registry import Opentide

__all__ = ["__version__", "Opentide"]


def __getattr__(name: str) -> object:
    """Keep ``OpenTide``, the spelling through 0.16.0, importable with a warning."""
    if name == "OpenTide":
        import warnings

        warnings.warn(
            "OpenTide is now Opentide; the old spelling will be removed in a later release.",
            DeprecationWarning,
            stacklevel=2,
        )
        return Opentide
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
