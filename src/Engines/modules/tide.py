"""Backward-compatibility re-export shim — delegates to opentide core."""

import warnings

warnings.warn(
    "Import from 'opentide' instead: from opentide import OpenTide",
    DeprecationWarning,
    stacklevel=2,
)

from opentide.core.index_manager import IndexManager
from opentide.core.registry import OpenTide
from opentide.loading.compat import ObjectLoader, TideLoader

DataTide = OpenTide

from Engines.modules.environment import DebugHelpers

HelperTide = DebugHelpers

from Engines.modules.enums import DetectionPlatforms

DetectionSystems = DetectionPlatforms

IndexTide = IndexManager


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
