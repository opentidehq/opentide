"""Defender For Endpoint platform."""

from __future__ import annotations

from typing import Any

__all__ = ["declare"]


def declare(*args: Any, **kwargs: Any) -> Any:
    from opentide.platforms.defender_for_endpoint.deployer import declare as _declare

    return _declare(*args, **kwargs)
