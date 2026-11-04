"""The time window of a query: ``--since`` or ``--from``/``--to``."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from opentide.core.time import utc_now
from opentide.platforms.elastic.durations import duration_seconds
from opentide.query.models import TimeWindow

DEFAULT_SINCE = "24h"


class WindowError(ValueError):
    """A window the caller gave cannot be used; ``flag`` is the option at fault."""

    def __init__(self, message: str, *, flag: str) -> None:
        super().__init__(message)
        self.flag = flag


def parse_instant(value: str, *, flag: str) -> datetime:
    """An ISO-8601 date or time as UTC; a time without an offset is UTC."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise WindowError(
            f"{flag} {value!r} is not an ISO-8601 time, such as 2026-10-27T08:00:00Z", flag=flag
        ) from None
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def resolve_window(
    since: str | None = None,
    start: str | None = None,
    end: str | None = None,
    *,
    now: datetime | None = None,
) -> TimeWindow:
    """The UTC window ``since`` (``15m``, ``24h``, ``7d``, ``PT1H``) or ``start``..``end`` name.

    ``since`` and ``start`` exclude each other. ``end`` without ``start``
    ends a ``since`` window there instead of now. Neither: the last 24 hours.
    """
    if since and start:
        raise WindowError("--since cannot be combined with --from", flag="--since")
    finish = parse_instant(end, flag="--to") if end else (now or utc_now())
    if start:
        begin = parse_instant(start, flag="--from")
    else:
        lookback = since or DEFAULT_SINCE
        try:
            seconds = duration_seconds(lookback)
        except ValueError:
            raise WindowError(
                f"--since {lookback!r} is not a duration, such as 15m, 24h, 7d or PT1H",
                flag="--since",
            ) from None
        begin = finish - timedelta(seconds=seconds)
    if begin >= finish:
        raise WindowError("--from must be earlier than --to", flag="--from")
    return TimeWindow(begin, finish)
