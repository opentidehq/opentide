"""Backward-compatibility re-export shim — delegates to opentide core."""

from opentide.core.index_manager import IndexManager
from opentide.core.registry import OpenTide

DataTide = OpenTide

from Engines.modules.environment import DebugHelpers

HelperTide = DebugHelpers

from Engines.modules.enums import DetectionPlatforms

DetectionSystems = DetectionPlatforms

IndexTide = IndexManager

from Engines.modules.loaders.object_loader import ObjectLoader

TideLoader = ObjectLoader


def _platforms():
    return OpenTide.Platforms


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
