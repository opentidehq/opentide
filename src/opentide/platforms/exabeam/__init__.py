"""Exabeam New-Scale SIEM platform: correlation rules (``platform::exabeam::1.0``)."""

from __future__ import annotations

from typing import Any

__all__ = ["declare"]


def declare(*args: Any, **kwargs: Any) -> Any:
    from opentide.platforms.exabeam.deployer import declare as _declare

    return _declare(*args, **kwargs)
