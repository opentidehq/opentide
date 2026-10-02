"""Review-instant parsing and the RFC 0008 unreviewed predicate.

``metadata.reviewed`` is stored on ``rule::1.1``. This module does not write
that field. Callers supply the evaluation instant and the window.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_WINDOW = re.compile(r"^(\d+)([dhm])?$")

RULE_10 = "rule::1.0"
RULE_11 = "rule::1.1"


def parse_review_instant(value: str) -> datetime:
    """Parse an ISO 8601 review timestamp.

    A date-only value is ``00:00:00Z`` on that date. Datetimes must carry ``Z``
    or a numeric offset. The result is timezone-aware UTC.
    """
    text = value.strip()
    if _DATE.fullmatch(text):
        parsed = datetime.strptime(text, "%Y-%m-%d")
        return parsed.replace(tzinfo=timezone.utc)
    if not _DATETIME.fullmatch(text):
        raise ValueError("metadata.reviewed must be an ISO 8601 date (YYYY-MM-DD) or datetime")
    normalized = text.replace("Z", "+00:00").replace(" ", "T")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("metadata.reviewed datetime must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def reviewed_text(value: Any) -> str | None:
    """Coerce a YAML review value to the string the predicate parses."""
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return str(value.isoformat())
    text = str(value).strip()
    return text or None


def parse_window(text: str) -> timedelta:
    """Parse a positive window such as ``90d``, ``12h``, ``30m``, or ``90`` (days)."""
    match = _WINDOW.fullmatch(text.strip())
    if match is None:
        raise ValueError("window must look like 90d, 12h, or 30m")
    count = int(match.group(1))
    if count <= 0:
        raise ValueError("window must be a positive duration")
    unit = match.group(2) or "d"
    if unit == "h":
        return timedelta(hours=count)
    if unit == "m":
        return timedelta(minutes=count)
    return timedelta(days=count)


def unreviewed_reason(
    schema_id: str,
    reviewed: str | None,
    *,
    now: datetime,
    window: timedelta,
) -> str | None:
    """Return why a rule is unreviewed, or ``None`` when it is inside the window.

    Reasons are ``schema`` (``rule::1.0``), ``absent``, or ``stale``.
    A review instant equal to ``now - window`` is not unreviewed.
    """
    if window <= timedelta(0):
        raise ValueError("window must be a positive duration")
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if schema_id == RULE_10:
        return "schema"
    if schema_id != RULE_11:
        return None
    if reviewed is None or not str(reviewed).strip():
        return "absent"
    instant = parse_review_instant(str(reviewed))
    if instant < now - window:
        return "stale"
    return None
