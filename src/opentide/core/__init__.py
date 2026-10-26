"""opentide runtime core — registry, index, and lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentide.core.registry import Opentide

__all__ = ["Opentide"]


def __getattr__(name: str) -> object:
    """Resolve ``Opentide`` on first use; keep ``OpenTide`` importable with a warning.

    Lazy so that importing any ``opentide.core`` submodule (``root``,
    ``logging``) does not load the registry.
    """
    if name == "Opentide":
        from opentide.core.registry import Opentide

        return Opentide
    if name == "OpenTide":
        import warnings

        from opentide.core.registry import Opentide

        warnings.warn(
            "OpenTide is now Opentide; the old spelling will be removed in a later release.",
            DeprecationWarning,
            stacklevel=2,
        )
        return Opentide
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
