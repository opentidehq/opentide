"""What ``validate query --live`` learns about each rule: its verdicts, as data.

A platform's live check (:class:`~opentide.platforms.live_validation.LiveQueryValidator`)
asks each tenant a rule deploys to whether it accepts the rule's queries, through
the platform's query runner, and returns one :class:`RuleCheck` per query and
tenant in a :class:`LiveCheckReport`. The CLI grades the run from the report;
:meth:`DetectionRule.validate_query` reads the same report. Nothing goes through
the process environment.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from opentide.core.time import utc_now
from opentide.query.models import TimeWindow

#: The window a live check searches: the last minute, so the search is cheap.
CHECK_WINDOW = timedelta(minutes=1)
#: Seconds one live check may take on a tenant (an asynchronous search, a slow
#: parse), unless ``--check-timeout`` or :data:`CHECK_TIMEOUT_ENV` sets another.
CHECK_TIMEOUT = 120.0
#: The environment variable that sets the check timeout when ``--check-timeout`` does not.
CHECK_TIMEOUT_ENV = "OPENTIDE_QUERY_CHECK_TIMEOUT"
#: Queries in a row on one tenant that get no answer in time (read timeouts)
#: before the tenant is reported unreachable and the run stops. One slow query
#: fails only itself; a tenant that answers none is not waited on for every rule.
UNREACHABLE_AFTER_TIMEOUTS = 3
#: The code of a check that got no answer within the check timeout.
QUERY_CHECK_TIMEOUT = "query_check_timeout"


def parse_timeout(value: str | float, *, source: str) -> float:
    """*value* as a number of seconds, or ``ValueError`` naming *source* when it is not one.

    A timeout is a positive, finite number: ``0``, a negative number, ``nan``
    and ``inf`` are refused, as is anything that is not a number.
    """
    try:
        seconds = float(value.strip() if isinstance(value, str) else value)
    except ValueError:
        seconds = math.nan
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError(f"{source} must be a positive number of seconds, got {value!r}")
    return seconds


def check_timeout(value: str | float | None = None) -> float:
    """The seconds a live check waits on each query.

    *value* (``--check-timeout``) when given, else :data:`CHECK_TIMEOUT_ENV`
    when set, else :data:`CHECK_TIMEOUT`. Raises ``ValueError`` for a value
    that is not a positive number.
    """
    if value is not None:
        return parse_timeout(value, source="--check-timeout")
    raw = os.environ.get(CHECK_TIMEOUT_ENV, "")
    if raw.strip():
        return parse_timeout(raw, source=CHECK_TIMEOUT_ENV)
    return CHECK_TIMEOUT


def check_window(now: datetime | None = None) -> TimeWindow:
    """The minute before *now* (default: the current time)."""
    end = now or utc_now()
    return TimeWindow(start=end - CHECK_WINDOW, end=end)


@dataclass(frozen=True)
class RuleCheck:
    """One rule's query, checked on one tenant.

    ``errors`` say why the tenant refused it (or why the rule could not be
    sent); ``warnings`` are reservations that do not fail the check. ``code``
    names a failure that is not a refusal: :data:`QUERY_CHECK_TIMEOUT` for a
    query that got no answer in time.
    """

    rule: str
    name: str
    tenant: str
    label: str | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    code: str | None = None

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
        if self.code is not None:
            payload["code"] = self.code
        return payload


@dataclass
class LiveCheckReport:
    """Every rule check one platform's live validation ran."""

    platform: str
    checks: list[RuleCheck] = field(default_factory=list)
    #: The seconds each check could wait for its answer.
    timeout: float = CHECK_TIMEOUT

    @property
    def failed(self) -> bool:
        """A tenant refused a query."""
        return any(not check.ok for check in self.checks)

    @property
    def warned(self) -> bool:
        return any(check.warnings for check in self.checks)

    def rejected(self) -> list[RuleCheck]:
        return [check for check in self.checks if not check.ok]

    def timed_out(self) -> list[RuleCheck]:
        """The checks that got no answer within :attr:`timeout`."""
        return [check for check in self.checks if check.code == QUERY_CHECK_TIMEOUT]

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "failed": self.failed,
            "warned": self.warned,
            "timeout": self.timeout,
            "checks": [check.to_dict() for check in self.checks],
        }
