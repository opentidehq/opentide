"""OpenTide DetectionOps engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentide._version import __version__

__all__ = ["__version__", "OpenTide"]


def __getattr__(name: str):
    if name == "OpenTide":
        import sys
        from pathlib import Path

        import git

        root = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
        root_str = str(root)
        if root_str not in sys.path:
            sys.path.append(root_str)
        from Engines.modules.platforms import Platforms
        from Engines.modules.registry import OpenTide

        OpenTide.Platforms = Platforms  # type: ignore[attr-defined]
        return OpenTide
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:
    from Engines.modules.registry import OpenTide
