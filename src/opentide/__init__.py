"""opentide DetectionOps engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentide._version import __version__

if TYPE_CHECKING:
    from opentide.core.registry import Opentide

__all__ = ["Opentide", "__version__"]


def __getattr__(name: str) -> object:
    """Resolve ``Opentide`` on first use; keep ``OpenTide`` importable with a warning.

    Lazy so that ``import opentide`` (which every ``opentide.*`` import runs)
    does not load the registry: ``opentide --version`` and ``--help`` never
    need it.
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
