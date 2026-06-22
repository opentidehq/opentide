"""Backward-compatibility re-export shim for tide module."""

from Engines.modules.enums import DetectionPlatforms
DetectionSystems = DetectionPlatforms  # legacy

from Engines.modules.registry import OpenTide
DataTide = OpenTide  # legacy

from Engines.modules.index import IndexManager
IndexTide = IndexManager  # legacy

from Engines.modules.environment import DebugHelpers
HelperTide = DebugHelpers  # legacy

from Engines.modules.loaders.object_loader import ObjectLoader
TideLoader = ObjectLoader  # legacy

def _platforms():
    from Engines.modules.platforms import Platforms
    OpenTide.Platforms = Platforms
    return Platforms

def __getattr__(name: str):
    if name == "Platforms":
        return _platforms()
    raise AttributeError(name)

__all__ = [
    "OpenTide",
    "DataTide",
    "IndexManager",
    "IndexTide",
    "DebugHelpers",
    "HelperTide",
    "ObjectLoader",
    "TideLoader",
    "DetectionPlatforms",
    "DetectionSystems",
    "Platforms",
]
