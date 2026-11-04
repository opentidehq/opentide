"""Live query validation for Sentinel: each rule's KQL, run for one row on its workspaces."""

from __future__ import annotations

from typing import ClassVar

from opentide.platforms.live_validation import LiveQueryValidator


class SentinelQueryValidator(LiveQueryValidator):
    platform: ClassVar[str] = "sentinel"


def declare() -> SentinelQueryValidator:
    return SentinelQueryValidator()
