"""Publish Tide objects to intelligence platforms.

Sharing is a sibling of deployment. Configuration lives in ``sharing.toml``
and is loaded by :mod:`opentide.sharing.config`, not by the generic
configuration deep-merge.
"""

from opentide.sharing.config import SharingConfig, load_sharing

__all__ = ["SharingConfig", "load_sharing"]
