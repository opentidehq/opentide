"""Live query validation for Exabeam: each sequence's filter, checked by Search on its tenants.

Each sequence query of a rule is sent as the ``filter`` of ``POST
/search/v2/events`` over the last 15 minutes, the window the console's "Test
Last 15 mins" uses (the runner's ``check``). Only the filter is checked: the
condition, windows, grouping and outcomes are not, because no Exabeam API
previews a rule (exabeam-1.0, Query validation).
"""

from __future__ import annotations

from typing import ClassVar

from opentide.models.rule import DetectionRule
from opentide.models.system_config import SystemConfig
from opentide.platforms.live_validation import LiveQueryValidator, TimeoutStreak
from opentide.query.check import RuleCheck
from opentide.query.models import TimeWindow


class ExabeamQueryValidator(LiveQueryValidator):
    platform: ClassVar[str] = "exabeam"

    def check_rule(
        self,
        rule: DetectionRule,
        tenant: SystemConfig.Tenant,
        window: TimeWindow,
        *,
        streak: TimeoutStreak | None = None,
    ) -> list[RuleCheck]:
        """*rule*'s sequence filters on *tenant*, over the 15 minutes before the window's end."""
        from opentide.platforms.exabeam.compile import LIVE_WINDOW

        window = TimeWindow(start=window.end - LIVE_WINDOW, end=window.end)
        return super().check_rule(rule, tenant, window, streak=streak)


def declare() -> ExabeamQueryValidator:
    return ExabeamQueryValidator()
