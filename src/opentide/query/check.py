"""What ``validate query --live`` learns about each rule: its verdicts, as data.

A platform's live check (:class:`~opentide.platforms.live_validation.LiveQueryValidator`)
asks each tenant a rule deploys to whether it accepts the rule's queries, through
the platform's query runner, and returns one :class:`RuleCheck` per query and
tenant in a :class:`LiveCheckReport`. The CLI grades the run from the report;
:meth:`DetectionRule.validate_query` reads the same report. Nothing goes through
the process environment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from opentide.core.time import utc_now
from opentide.query.models import TimeWindow

#: The window a live check searches: the last minute, so the search is cheap.
CHECK_WINDOW = timedelta(minutes=1)
#: Seconds one live check may take on a tenant (an asynchronous search, a slow parse).
CHECK_TIMEOUT = 120.0


def check_window(now: datetime | None = None) -> TimeWindow:
    """The minute before *now* (default: the current time)."""
    end = now or utc_now()
    return TimeWindow(start=end - CHECK_WINDOW, end=end)


@dataclass(frozen=True)
class RuleCheck:
    """One rule's query, checked on one tenant.

    ``errors`` say why the tenant refused it (or why the rule could not be
    sent); ``warnings`` are reservations that do not fail the check.
    """

    rule: str
    name: str
    tenant: str
    label: str | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule": self.rule,
            "name": self.name,
            "tenant": self.tenant,
            "status": "passed" if self.ok else "failed",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }
        if self.label is not None:
            payload["label"] = self.label
        return payload


@dataclass
class LiveCheckReport:
    """Every rule check one platform's live validation ran."""

    platform: str
    checks: list[RuleCheck] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        """A tenant refused a query."""
        return any(not check.ok for check in self.checks)

    @property
    def warned(self) -> bool:
        return any(check.warnings for check in self.checks)

    def rejected(self) -> list[RuleCheck]:
        return [check for check in self.checks if not check.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "failed": self.failed,
            "warned": self.warned,
            "checks": [check.to_dict() for check in self.checks],
        }
