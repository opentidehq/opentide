"""Duration parser and formatting for Elastic Security detection rules."""

from __future__ import annotations

import re

UNIT_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}
_SHORT_DURATION = re.compile(r"(\d+)([smhd])")
_ISO_DURATION = re.compile(r"P(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")


def duration_seconds(value: str, *, allow_zero: bool = False) -> int:
    """Parse a duration string into integer seconds.

    Accepts '<n>s|m|h|d' or ISO 8601 ('PT1H', 'P14D').
    Rejects negative values and, unless allow_zero is True, zero values.
    """
    if not isinstance(value, str):
        raise ValueError(f"Duration must be a string, got {type(value).__name__}")
    if short := _SHORT_DURATION.fullmatch(value):
        total = int(short.group(1)) * UNIT_SECONDS[short.group(2)]
    elif (match := _ISO_DURATION.fullmatch(value)) and value not in ("P", "PT"):
        days, hours, minutes, secs = (int(g or 0) for g in match.groups())
        total = ((days * 24 + hours) * 60 + minutes) * 60 + secs
    else:
        raise ValueError(f"Invalid duration format: {value!r}")
    if total < 0 or (total == 0 and not allow_zero):
        raise ValueError(f"Duration must be positive (or zero if allowed): {value!r}")
    return total


def format_duration(total: int) -> str:
    """Format total seconds using the largest exact unit among d, h, m, s."""
    if total == 0:
        return "0s"
    for unit in "dhms":
        size = UNIT_SECONDS[unit]
        if total % size == 0:
            return f"{total // size}{unit}"
    raise AssertionError("unreachable: seconds always divide")


def elastic_duration(value: str, units: str = "dhms") -> tuple[int, str]:
    """Convert a duration string to an (amount, unit) tuple using allowed units."""
    total = duration_seconds(value)
    for unit in units:
        if total % UNIT_SECONDS[unit] == 0:
            return total // UNIT_SECONDS[unit], unit
    raise AssertionError(f"Duration {value!r} cannot be represented in units {units!r}")


def date_math(value: str, units: str = "dhms") -> str:
    """Format a duration string as Elastic date math amount+unit (e.g. '5m', '1h')."""
    amount, unit = elastic_duration(value, units)
    return f"{amount}{unit}"
