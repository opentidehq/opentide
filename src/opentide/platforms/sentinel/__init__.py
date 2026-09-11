"""Sentinel platform."""

from __future__ import annotations

from typing import Any

__all__ = ["declare"]


def __getattr__(name: str) -> Any:
    if name == "declare":
        from opentide.platforms.sentinel.deployer import declare

        return declare
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
