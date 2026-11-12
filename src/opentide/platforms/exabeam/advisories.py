"""Exabeam advisories (exabeam-1.0, Advisories): warnings that never reject a rule.

Exabeam accepts each of these, but the rule then does not do what its author
most likely meant. ``opentide validate`` reports them as warnings, and
``opentide lint`` with its ``queries`` check.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from opentide.platforms.exabeam.constraints import as_authored, duration

OUTCOME_SILENT = "exabeam_outcome_silent"
CORRELATION_WINDOW = "exabeam_correlation_window"

ADVISORY_CODES = frozenset({OUTCOME_SILENT, CORRELATION_WINDOW})

_BLOCK = ("configurations", "exabeam")
_MINUTES = {"m": 1, "h": 60, "d": 1440}


@dataclass(frozen=True)
class Advisory:
    code: str
    field_path: tuple[str, ...]
    message: str


def _minutes(value: Any) -> int | None:
    parsed = duration(value, "mhd")
    return parsed[0] * _MINUTES[parsed[1]] if parsed is not None else None


def exabeam_advisories(rule: Mapping[str, Any]) -> list[Advisory]:
    """Every advisory the rule's ``exabeam`` block, as authored, earns."""
    configurations = rule.get("configurations")
    block = configurations.get("exabeam") if isinstance(configurations, Mapping) else None
    if not isinstance(block, Mapping):
        return []
    raw = as_authored(block)
    found: list[Advisory] = []
    if raw.get("outcome") == "none" and "email" not in raw:
        found.append(
            Advisory(
                OUTCOME_SILENT,
                (*_BLOCK, "outcome"),
                "outcome: none and no email: the rule only writes a rule-trigger event, which "
                "nobody is told about",
            )
        )
    correlation = raw.get("correlation")
    sequences = raw.get("sequences")
    if isinstance(correlation, Mapping) and isinstance(sequences, list):
        window = _minutes(correlation.get("within"))
        longest: tuple[int, str] | None = None
        for sequence in sequences:
            threshold = sequence.get("threshold") if isinstance(sequence, Mapping) else None
            within = threshold.get("within") if isinstance(threshold, Mapping) else None
            minutes = _minutes(within)
            if minutes is not None and (longest is None or minutes > longest[0]):
                longest = (minutes, str(within))
        if window is not None and longest is not None and window < longest[0]:
            found.append(
                Advisory(
                    CORRELATION_WINDOW,
                    (*_BLOCK, "correlation", "within"),
                    f"correlation.within {correlation.get('within')} is shorter than the longest "
                    f"sequence window, {longest[1]}: Exabeam asks for at least the longest one",
                )
            )
    return found
