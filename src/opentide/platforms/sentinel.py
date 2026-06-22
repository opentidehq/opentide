"""Microsoft Sentinel platform plugin."""

from __future__ import annotations

from typing import Any


def declare() -> Any:
    from Engines.deployment.sentinel import declare as _declare

    return _declare()
