"""Microsoft Defender for Endpoint platform plugin."""

from __future__ import annotations

from typing import Any


def declare() -> Any:
    from Engines.deployment.defender_for_endpoint import declare as _declare

    return _declare()
