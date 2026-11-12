"""The ``configurations.exabeam`` block checks (exabeam-1.0, Constraints).

Static validation of a block as authored: every constraint code of the spec
but the workspace check ``exabeam_name_duplicate``
(:mod:`opentide.validation.exabeam_names`). :func:`block_findings` reads the
raw block, so :class:`~opentide.models.platform.ExabeamConfig` reports every
code at once, before the field types run, each at the ``field_path`` the spec
fixes for it, relative to the block.

The sequence queries themselves are the analysis engine's: the Exabeam Query
Language (exabeam-1.0 language spec, profile ``rule``). The one query check
made here is ``exabeam_context_table_trigger``, a rule about the condition a
context-table lookup may take.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, NamedTuple


class Finding(NamedTuple):
    """A code, its path relative to ``configurations.exabeam``, and its message."""

    code: str
    path: tuple[str, ...]
    message: str


#: What each constraint code says (exabeam-1.0, Constraints).
CODE_MESSAGES: dict[str, str] = {
    "exabeam_sequences": "sequences is a non-empty list, and every sequence has a non-blank query",
    "exabeam_correlation": ("correlation is set with two or more sequences and left out with one"),
    "exabeam_threshold_function": (
        "threshold.function is count, unique_count, value, max, min, sum or average, and "
        "field is set unless the function is count"
    ),
    "exabeam_threshold_operator": "threshold.operator is not one the function takes",
    "exabeam_threshold_value": "threshold.value does not have the shape its operator takes",
    "exabeam_group_by": "group_by is a list of one to three distinct non-blank field names",
    "exabeam_duration": "not a duration this field takes",
    "exabeam_severity": "severity is none, low, medium, high or critical",
    "exabeam_outcome": "outcome is alert, case or none",
    "exabeam_email": (
        "email.recipients is a non-empty list of distinct addresses, and subject is "
        "non-blank when set"
    ),
    "exabeam_schedule": "not a valid recurrence",
    "exabeam_name_length": "the Exabeam rule name is at most 128 characters",
    "exabeam_context_table_trigger": (
        'a sequence whose query looks up a context table (IN "…") triggers on any match: '
        "remove its threshold"
    ),
}

#: Every code :func:`block_findings` reports.
CONSTRAINT_CODES: frozenset[str] = frozenset(CODE_MESSAGES)

FUNCTIONS: tuple[str, ...] = ("count", "unique_count", "value", "max", "min", "sum", "average")
NUMERIC_OPERATORS: tuple[str, ...] = ("more_than", "less_than")
VALUE_OPERATORS: tuple[str, ...] = ("in", "not_in")
#: Functions that compare with a non-negative integer.
INTEGRAL_FUNCTIONS: frozenset[str] = frozenset({"count", "unique_count"})
SEVERITIES: tuple[str, ...] = ("none", "low", "medium", "high", "critical")
OUTCOMES: tuple[str, ...] = ("alert", "case", "none")
WEEKDAYS: tuple[str, ...] = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)
#: The day keys each ``every`` takes (exabeam-1.0, ``schedule[]``).
RECURRENCE_DAY_KEYS: dict[str, frozenset[str]] = {
    "day": frozenset(),
    "week": frozenset({"days"}),
    "month": frozenset({"days", "last_day"}),
    "days": frozenset({"first", "last"}),
}

NAME_LIMIT = 128
GROUP_BY_LIMIT = 3
#: ``delay`` in minutes (exabeam-1.0, Durations).
DELAY_MINUTES = (7, 180)

UNITS: dict[str, str] = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}

_DURATION = re.compile(r"([1-9][0-9]*)([mhdw])")
_TIME = re.compile(r"([01]?[0-9]|2[0-3]):[0-5][0-9]Z")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_IN_KEYWORD = re.compile(r"(?i)(?<![A-Za-z0-9_.-])IN\s*$")


def duration(value: Any, units: str) -> tuple[int, str] | None:
    """``(number, unit letter)`` for a duration whose unit is in *units*, else ``None``.

    A duration is a positive whole number and one unit, no space: ``30m``,
    ``4h``, ``1d``, ``2w``. Compound and ISO 8601 durations are not.
    """
    if not isinstance(value, str):
        return None
    match = _DURATION.fullmatch(value)
    if match is None or match.group(2) not in units:
        return None
    return int(match.group(1)), match.group(2)


def delay_minutes(value: Any) -> int | None:
    """``delay`` in minutes, or ``None`` when it is not a duration in ``m`` or ``h``."""
    parsed = duration(value, "mh")
    if parsed is None:
        return None
    return parsed[0] * (60 if parsed[1] == "h" else 1)


def uses_context_table(query: str) -> bool:
    """Whether *query* looks a value up in a context table: ``field IN "Table"``.

    Text inside a double- or single-quoted string is not read, so a phrase
    that holds ``IN "`` is not a lookup.
    """
    code: list[str] = []
    index = 0
    while index < len(query):
        char = query[index]
        if char in "\"'":
            if _IN_KEYWORD.search("".join(code)):
                return True
            end = index + 1
            while end < len(query) and query[end] != char:
                end += 2 if query[end] == "\\" else 1
            code.append(" ")
            index = end + 1
            continue
        code.append(char)
        index += 1
    return False


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _group_by_ok(value: Any, *, allow_empty: bool) -> bool:
    if not isinstance(value, list) or len(value) > GROUP_BY_LIMIT:
        return False
    if not value and not allow_empty:
        return False
    if not all(isinstance(item, str) and item.strip() for item in value):
        return False
    return len(set(value)) == len(value)


def _threshold_findings(threshold: Any, path: tuple[str, ...]) -> list[Finding]:
    def found(code: str, message: str | None = None) -> Finding:
        return Finding(code, path, message or CODE_MESSAGES[code])

    if not isinstance(threshold, Mapping):
        return [found("exabeam_threshold_function", "threshold is a table")]
    findings: list[Finding] = []
    function = threshold.get("function")
    if function not in FUNCTIONS:
        return [
            found(
                "exabeam_threshold_function",
                f"{function!r} is not an Exabeam function: {', '.join(FUNCTIONS)}",
            )
        ]
    field_name = threshold.get("field")
    if field_name is not None and not (isinstance(field_name, str) and field_name.strip()):
        findings.append(found("exabeam_threshold_function", "field is a non-blank string"))
    elif field_name is None and function != "count":
        findings.append(found("exabeam_threshold_function", f"{function} reads a field: set field"))
    operator = threshold.get("operator")
    allowed = VALUE_OPERATORS if function == "value" else NUMERIC_OPERATORS
    if operator not in allowed:
        findings.append(
            found(
                "exabeam_threshold_operator",
                f"{function} takes the operator {' or '.join(allowed)}, not {operator!r}",
            )
        )
    else:
        value = threshold.get("value")
        if operator in NUMERIC_OPERATORS:
            integral = function in INTEGRAL_FUNCTIONS
            ok = _number(value) and (
                not integral
                or (isinstance(value, int) and not isinstance(value, bool) and value >= 0)
            )
            shape = "a non-negative integer" if integral else "a number"
        else:
            ok = (
                isinstance(value, list)
                and bool(value)
                and all(
                    (isinstance(item, str) and item.strip() and "," not in item) or _number(item)
                    for item in value
                )
            )
            shape = "a non-empty list of strings (without commas) or numbers"
        if not ok:
            findings.append(
                found("exabeam_threshold_value", f"{function} {operator} compares with {shape}")
            )
    if duration(threshold.get("within"), "mhd") is None:
        findings.append(
            Finding(
                "exabeam_duration",
                (*path, "within"),
                "within is a whole number of minutes, hours or days: 30m, 4h, 1d",
            )
        )
    return findings


def _sequence_findings(sequences: Any) -> list[Finding]:
    if not isinstance(sequences, list) or not sequences:
        return [
            Finding(
                "exabeam_sequences", ("sequences",), "sequences is a non-empty list of sequences"
            )
        ]
    findings: list[Finding] = []
    for index, sequence in enumerate(sequences):
        path = ("sequences", str(index))
        if not isinstance(sequence, Mapping):
            findings.append(
                Finding("exabeam_sequences", path, "a sequence is a table with a query")
            )
            continue
        query = sequence.get("query")
        if not isinstance(query, str) or not query.strip():
            findings.append(
                Finding("exabeam_sequences", (*path, "query"), "query is a non-blank string")
            )
        if "group_by" in sequence and not _group_by_ok(sequence["group_by"], allow_empty=False):
            findings.append(
                Finding("exabeam_group_by", (*path, "group_by"), CODE_MESSAGES["exabeam_group_by"])
            )
        if "threshold" in sequence:
            threshold_path = (*path, "threshold")
            findings.extend(_threshold_findings(sequence["threshold"], threshold_path))
            if isinstance(query, str) and uses_context_table(query):
                findings.append(
                    Finding(
                        "exabeam_context_table_trigger",
                        threshold_path,
                        CODE_MESSAGES["exabeam_context_table_trigger"],
                    )
                )
    return findings


def _correlation_findings(correlation: Any, count: int) -> list[Finding]:
    path = ("correlation",)
    if count >= 2 and correlation is None:
        return [
            Finding(
                "exabeam_correlation",
                path,
                f"{count} sequences correlate within a window: set correlation.within",
            )
        ]
    if count == 1 and correlation is not None:
        return [
            Finding(
                "exabeam_correlation",
                path,
                "one sequence has nothing to correlate with: remove correlation",
            )
        ]
    if correlation is None:
        return []
    if not isinstance(correlation, Mapping):
        return [Finding("exabeam_correlation", path, "correlation is a table with within")]
    findings: list[Finding] = []
    if duration(correlation.get("within"), "mhd") is None:
        findings.append(
            Finding(
                "exabeam_duration",
                (*path, "within"),
                "within is a whole number of minutes, hours or days: 15m, 1h, 1d",
            )
        )
    if "group_by" in correlation and not _group_by_ok(correlation["group_by"], allow_empty=True):
        findings.append(
            Finding(
                "exabeam_group_by",
                (*path, "group_by"),
                "correlation.group_by is a list of up to three distinct non-blank field names",
            )
        )
    return findings


def _email_ok(email: Any) -> bool:
    if not isinstance(email, Mapping):
        return False
    recipients = email.get("recipients")
    if not isinstance(recipients, list) or not recipients:
        return False
    if not all(isinstance(item, str) and _EMAIL.fullmatch(item) for item in recipients):
        return False
    if len(set(recipients)) != len(recipients):
        return False
    subject = email.get("subject")
    if subject is not None and not (isinstance(subject, str) and subject.strip()):
        return False
    return isinstance(email.get("attach_csv", False), bool)


def _suppression_findings(suppression: Any) -> list[Finding]:
    path = ("suppression",)
    if not isinstance(suppression, Mapping):
        return [Finding("exabeam_duration", path, "suppression is a table with for")]
    findings: list[Finding] = []
    if duration(suppression.get("for"), "mhdw") is None:
        findings.append(
            Finding(
                "exabeam_duration",
                (*path, "for"),
                "for is a whole number of minutes, hours, days or weeks: 30m, 1h, 1d, 2w",
            )
        )
    if "group_by" in suppression and not _group_by_ok(suppression["group_by"], allow_empty=False):
        findings.append(
            Finding("exabeam_group_by", (*path, "group_by"), CODE_MESSAGES["exabeam_group_by"])
        )
    return findings


def _distinct(values: list[Any]) -> bool:
    return len({repr(value) for value in values}) == len(values)


def _recurrence_problem(recurrence: Any) -> str | None:
    """Why *recurrence* is not a valid ``schedule[]`` entry, or ``None``."""
    every = recurrence.get("every") if isinstance(recurrence, Mapping) else None
    # A list or a map under ``every`` is unhashable: test the type before the lookup.
    if not isinstance(every, str) or every not in RECURRENCE_DAY_KEYS:
        return "every is day, week, month or days"
    for key in ("from", "to"):
        value = recurrence.get(key)
        if not isinstance(value, str) or _TIME.fullmatch(value) is None:
            return f"{key} is a UTC time written HH:MMZ, such as 08:00Z"
    extra = set(recurrence) - {"every", "from", "to"} - RECURRENCE_DAY_KEYS[every]
    if extra:
        return f"a {every} recurrence does not take {', '.join(sorted(map(str, extra)))}"
    if every == "week":
        days = recurrence.get("days")
        if (
            not isinstance(days, list)
            or not days
            or not _distinct(days)
            or not all(day in WEEKDAYS for day in days)
        ):
            return "a week recurrence has days: distinct weekday names, monday to sunday"
    elif every == "month":
        days = recurrence.get("days")
        last_day = recurrence.get("last_day", False)
        if not isinstance(last_day, bool):
            return "last_day is true or false"
        if days is None and not last_day:
            return "a month recurrence has days, last_day: true, or both"
        if days is not None and (
            not isinstance(days, list)
            or not days
            or not _distinct(days)
            or not all(
                isinstance(day, int) and not isinstance(day, bool) and 1 <= day <= 31
                for day in days
            )
        ):
            return "a month recurrence's days are distinct day numbers, 1 to 31"
    elif every == "days":
        if recurrence.get("first") not in WEEKDAYS or recurrence.get("last") not in WEEKDAYS:
            return "a days recurrence has first and last: weekday names, monday to sunday"
    return None


def _schedule_findings(schedule: Any) -> list[Finding]:
    if not isinstance(schedule, list) or not schedule:
        return [Finding("exabeam_schedule", ("schedule",), "schedule is a non-empty list")]
    findings: list[Finding] = []
    for index, recurrence in enumerate(schedule):
        problem = _recurrence_problem(recurrence)
        if problem is not None:
            findings.append(Finding("exabeam_schedule", ("schedule", str(index)), problem))
    return findings


def as_authored(value: Any) -> Any:
    """*value* as the author wrote it, with null keys left out.

    A key whose value is null is left out, at every level: it is the key not
    written, which is how a model dump writes every optional key. The keyword
    keys ``for`` and ``from`` are read only by those names: ``for_`` and
    ``from_`` are unknown keys, and the models dump the YAML names.
    """
    if isinstance(value, Mapping):
        return {key: as_authored(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [as_authored(item) for item in value]
    return value


def block_findings(block: Mapping[str, Any]) -> list[Finding]:
    """Every exabeam-1.0 constraint finding of a block, as authored, at its path.

    A null is the key left out (:func:`as_authored`), at the root and inside
    every table.
    """
    raw = as_authored(block)
    findings = _sequence_findings(raw.get("sequences"))
    sequences = raw.get("sequences")
    count = len(sequences) if isinstance(sequences, list) else 0
    findings.extend(_correlation_findings(raw.get("correlation"), count))
    severity = raw.get("severity")
    if severity is not None and severity not in SEVERITIES:
        findings.append(
            Finding(
                "exabeam_severity",
                ("severity",),
                f"{severity!r} is not an Exabeam severity: {', '.join(SEVERITIES)} (lower case)",
            )
        )
    outcome = raw.get("outcome")
    if outcome is not None and outcome not in OUTCOMES:
        findings.append(
            Finding("exabeam_outcome", ("outcome",), f"{outcome!r} is not alert, case or none")
        )
    if "email" in raw and not _email_ok(raw["email"]):
        findings.append(Finding("exabeam_email", ("email",), CODE_MESSAGES["exabeam_email"]))
    if "suppression" in raw:
        findings.extend(_suppression_findings(raw["suppression"]))
    if "delay" in raw:
        minutes = delay_minutes(raw["delay"])
        low, high = DELAY_MINUTES
        if minutes is None or not low <= minutes <= high:
            findings.append(
                Finding(
                    "exabeam_duration",
                    ("delay",),
                    f"delay is {low} to {high} minutes, written in m or h: 7m to 180m, 1h to 3h",
                )
            )
    if "schedule" in raw:
        findings.extend(_schedule_findings(raw["schedule"]))
    name = raw.get("name")
    if isinstance(name, str) and len(name) > NAME_LIMIT:
        findings.append(name_length_finding(name))
    return findings


def name_length_finding(name: str) -> Finding:
    """``exabeam_name_length`` for an Exabeam rule name longer than 128 characters."""
    return Finding(
        "exabeam_name_length",
        ("name",),
        f"the Exabeam rule name is {len(name)} characters, more than {NAME_LIMIT}: set a "
        "shorter configurations.exabeam.name",
    )


def block_codes(block: Mapping[str, Any]) -> set[str]:
    """Every exabeam-1.0 constraint code a block, as authored, breaks."""
    return {finding.code for finding in block_findings(block)}
