"""Graylog platform: event definitions, Filter & Aggregation (``platform::graylog::1.0``)."""

from __future__ import annotations

from typing import Any

__all__ = ["declare"]


def declare(*args: Any, **kwargs: Any) -> Any:
    from opentide.platforms.graylog.deployer import declare as _declare

    return _declare(*args, **kwargs)
