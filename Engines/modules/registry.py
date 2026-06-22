"""Legacy registry shim — delegates to opentide.core.registry."""

from opentide.core.registry import OpenTide

DataTide = OpenTide

from opentide.platforms.registry import PlatformsRegistry

Platforms = PlatformsRegistry()
OpenTide.Platforms = Platforms

__all__ = ["OpenTide", "DataTide", "Platforms"]
