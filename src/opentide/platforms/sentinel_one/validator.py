"""Live query validation for SentinelOne: each rule's queries, run for one row on its tenants.

A correlation rule's sub-queries are checked one by one.
"""

from __future__ import annotations

from typing import ClassVar

from opentide.platforms.live_validation import LiveQueryValidator


class SentinelOneQueryValidator(LiveQueryValidator):
    platform: ClassVar[str] = "sentinel_one"


def declare() -> SentinelOneQueryValidator:
    return SentinelOneQueryValidator()
