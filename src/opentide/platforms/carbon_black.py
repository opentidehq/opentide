"""Carbon Black Cloud platform plugin."""

from __future__ import annotations

from typing import Any


def declare() -> Any:
    from Engines.deployment.carbon_black_cloud import declare as _declare

    return _declare()
