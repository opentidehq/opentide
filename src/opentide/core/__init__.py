"""opentide runtime core — registry, index, and lifecycle."""

from opentide.core.registry import Opentide

__all__ = ["Opentide"]


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
