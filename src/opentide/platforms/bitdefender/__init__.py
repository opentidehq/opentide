"""Bitdefender GravityZone platform: custom detection rules (``platform::bitdefender::1.0``)."""

from __future__ import annotations

from typing import Any

__all__ = ["declare"]


def declare(*args: Any, **kwargs: Any) -> Any:
    from opentide.platforms.bitdefender.deployer import declare as _declare

    return _declare(*args, **kwargs)
