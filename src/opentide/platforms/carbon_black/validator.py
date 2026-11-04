"""Live query validation for Carbon Black Cloud: each rule's query, parsed by its tenants.

The check is Carbon Black's ``search_validation`` call (the runner's ``check``),
so no process search runs.
"""

from __future__ import annotations

from typing import ClassVar

from opentide.platforms.live_validation import LiveQueryValidator


class CarbonBlackCloudQueryValidator(LiveQueryValidator):
    platform: ClassVar[str] = "carbon_black_cloud"


def declare() -> CarbonBlackCloudQueryValidator:
    return CarbonBlackCloudQueryValidator()
