"""Live query validation for Graylog: each rule's query, checked by its tenants.

The check is ``POST /api/search/validate`` (the runner's ``check``), with the
block's streams and a relative range of the block's ``window``, so no search
runs (graylog-1.0, Query validation).
"""

from __future__ import annotations

from datetime import timedelta
from typing import ClassVar

from opentide.models.rule import DetectionRule
from opentide.models.system_config import SystemConfig
from opentide.platforms.live_validation import LiveQueryValidator, TimeoutStreak
from opentide.query.check import RuleCheck
from opentide.query.models import TimeWindow


class GraylogQueryValidator(LiveQueryValidator):
    platform: ClassVar[str] = "graylog"

    def check_rule(
        self,
        rule: DetectionRule,
        tenant: SystemConfig.Tenant,
        window: TimeWindow,
        *,
        streak: TimeoutStreak | None = None,
    ) -> list[RuleCheck]:
        """*rule*'s query on *tenant*, over the block's ``window`` (``every``, else 5m)."""
        from opentide.platforms.graylog.compile import window_ms

        block = rule.platform_configs().graylog
        if block is not None:
            span = timedelta(milliseconds=window_ms(block))
            window = TimeWindow(start=window.end - span, end=window.end)
        return super().check_rule(rule, tenant, window, streak=streak)


def declare() -> GraylogQueryValidator:
    return GraylogQueryValidator()
