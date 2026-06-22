"""Splunk Enterprise platform plugin."""

from __future__ import annotations

from typing import Any


def declare() -> Any:
    from Engines.deployment.splunk import declare as _declare

    return _declare()
