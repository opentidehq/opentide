"""The Graylog block's constraints and condition grammar (graylog-1.0, Constraints).

:func:`block_findings` reports every constraint code of a block as authored,
each at the ``field_path`` the spec fixes for it, so ``opentide validate`` and
the editor name the same finding. :func:`parse_condition` compiles an
``aggregation.condition`` into Graylog's series and condition tree.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

#: A Graylog message field name (``Message.validKey``).
FIELD_NAME = re.compile(r"[A-Za-z0-9_.@-]+")

#: Block fields that take one string or a list of strings (graylog-1.0, List fields).
LIST_FIELDS: tuple[str, ...] = (
    "tags",
    "streams",
    "stream_categories",
    "event_key",
    "notifications",
)

PRIORITIES: dict[str, int] = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

#: Graylog's 12 aggregation functions, the same on every supported version.
FUNCTIONS = frozenset(
    {
        "avg",
        "card",
        "count",
        "latest",
        "max",
        "min",
        "percentage",
        "percentile",
        "stddev",
        "sum",
        "sumofsquares",
        "variance",
    }
)
OPERATORS = (">=", ">", "<=", "<", "==")

EVENT_LIMIT_MAX = 1000

CODE_MESSAGES: dict[str, str] = {
    "graylog_query_blank": "query must not be empty: it is the Graylog search query",
    "graylog_list_shape": "a string or a list of distinct, non-blank strings",
    "graylog_schedule": "schedule is invalid",
    "graylog_event_limit": "event_limit is an integer from 1 to 1,000, on a filter only",
    "graylog_aggregation": "aggregation needs a condition in the condition grammar",
    "graylog_event_field": (
        "an event field value is a field name, a string containing ${...}, {template}, or {lookup}"
    ),
    "graylog_event_key": "each event_key item is an event_fields name",
    "graylog_priority": "priority is Informational, Low, Medium, High, or Critical",
    "graylog_field_name": "each aggregation.group_by item is a field name",
}
CONSTRAINT_CODES: frozenset[str] = frozenset(CODE_MESSAGES)


class Finding(NamedTuple):
    """A code, its path relative to ``configurations.graylog``, and what is wrong."""

    code: str
    path: tuple[str, ...]
    message: str | None = None

    @property
    def text(self) -> str:
        return self.message or CODE_MESSAGES[self.code]


# --- list fields ---------------------------------------------------------------------------


def as_list(value: str | Sequence[str] | None) -> list[str]:
    """A string-or-list field as a list: a string is a one-item list, absent is empty."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def list_ok(value: Any) -> bool:
    """Whether *value* is absent, a non-blank string, or a list of distinct non-blank strings."""
    if value is None:
        return True
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list):
        return False
    if not all(isinstance(item, str) and item.strip() for item in items):
        return False
    return len(set(items)) == len(items)


# --- durations and cron ----------------------------------------------------------------------


def duration_ms(value: str, *, allow_zero: bool = False) -> int:
    """Milliseconds in an Elastic-grammar duration; ``ValueError`` when it is not one."""
    from opentide.platforms.elastic.durations import duration_seconds

    return duration_seconds(value, allow_zero=allow_zero) * 1000


def _positive_duration(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        duration_ms(value)
    except ValueError:
        return False
    return True


_MONTHS = ("JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC")
_DAYS = ("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT")
#: (low, high, names) of each Quartz field: seconds, minutes, hours, day of month,
#: month, day of week, year.
_CRON_FIELDS: tuple[tuple[int, int, tuple[str, ...]], ...] = (
    (0, 59, ()),
    (0, 59, ()),
    (0, 23, ()),
    (1, 31, ()),
    (1, 12, _MONTHS),
    (1, 7, _DAYS),
    (1970, 2099, ()),
)
_DAY_OF_MONTH, _DAY_OF_WEEK = 3, 5


def _cron_value(text: str, low: int, high: int, names: tuple[str, ...]) -> bool:
    upper = text.upper()
    if upper in names:
        return True
    return text.isdigit() and low <= int(text) <= high


def _cron_part(part: str, index: int) -> bool:
    low, high, names = _CRON_FIELDS[index]
    base, slash, step = part.partition("/")
    if slash and not (step.isdigit() and int(step) > 0):
        return False
    if base == "*":
        return True
    if index == _DAY_OF_MONTH and not slash:
        if base in ("L", "LW") or re.fullmatch(r"L-([0-9]{1,2})", base):
            return True
        if base.endswith("W") and _cron_value(base[:-1], low, high, names):
            return True
    if index == _DAY_OF_WEEK and not slash:
        if base == "L" or (base.endswith("L") and _cron_value(base[:-1], low, high, names)):
            return True
        day, hash_mark, nth = base.partition("#")
        if hash_mark:
            return _cron_value(day, low, high, names) and nth in ("1", "2", "3", "4", "5")
    start, dash, end = base.partition("-")
    if dash:
        return _cron_value(start, low, high, names) and _cron_value(end, low, high, names)
    return _cron_value(base, low, high, names)


def cron_ok(cron: Any) -> bool:
    """Whether *cron* is a Quartz expression of 6 or 7 fields.

    Each field takes ``*``, values, ranges, lists and steps in its own range
    (names for months and days), day of month ``L``, ``LW``, ``L-n`` and ``nW``,
    day of week ``L``, ``nL`` and ``n#k``. Quartz needs ``?`` in exactly one of
    day of month and day of week.
    """
    if not isinstance(cron, str):
        return False
    fields = cron.split()
    if len(fields) not in (6, 7):
        return False
    question = [index for index, text in enumerate(fields) if text == "?"]
    if question not in ([_DAY_OF_MONTH], [_DAY_OF_WEEK]):
        return False
    for index, text in enumerate(fields):
        if text == "?":
            continue
        if not all(part and _cron_part(part, index) for part in text.split(",")):
            return False
    return True


def timezone_ok(name: Any) -> bool:
    """Whether *name* is an IANA time zone name.

    Without a time zone database (Windows without ``tzdata``) every name that
    looks like one is accepted rather than every name refused.
    """
    if not isinstance(name, str) or not name.strip():
        return False
    import zoneinfo

    try:
        zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        if not zoneinfo.available_timezones():
            return bool(re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", name))
        return False
    return True


# --- condition grammar -----------------------------------------------------------------------


class ConditionError(ValueError):
    """The aggregation condition does not parse, or a call has the wrong arguments."""


_TOKEN = re.compile(r"\s*(?:(>=|<=|==|>|<|\(|\)|,)|([A-Za-z0-9_.@-]+))")
_NUMBER = re.compile(r"-?[0-9]+(?:\.[0-9]+)?")


def _number(token: str) -> int | float:
    if not _NUMBER.fullmatch(token):
        raise ConditionError(f"{token!r} is not a number")
    return float(token) if "." in token else int(token)


def _tokens(text: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(text):
        if not text[position:].strip():
            break
        match = _TOKEN.match(text, position)
        if match is None or match.end() == position:
            raise ConditionError(f"unexpected {text[position:].strip()[:12]!r}")
        tokens.append(match.group(1) or match.group(2))
        position = match.end()
    return tokens


#: How deep parentheses and ``NOT`` may nest (graylog-1.1, Condition grammar): the
#: parser recurses once per level, so an unbounded condition would raise RecursionError.
MAX_NESTING = 32


class _ConditionParser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.index = 0
        self.depth = 0
        self.series: list[dict[str, Any]] = []

    def nest(self) -> None:
        self.depth += 1
        if self.depth > MAX_NESTING:
            raise ConditionError(
                f"the condition nests deeper than {MAX_NESTING} levels of '(' and 'NOT'"
            )

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None or (expected is not None and token != expected):
            raise ConditionError(f"expected {expected or 'more'}, got {token!r}")
        self.index += 1
        return token

    def call(self) -> str:
        function = self.take()
        if function not in FUNCTIONS:
            raise ConditionError(f"{function!r} is not an aggregation function")
        self.take("(")
        # field [ "," number ]: arguments are separated by exactly one comma.
        args: list[str] = []
        if self.peek() != ")":
            args.append(self.take())
            while self.peek() == ",":
                self.take(",")
                args.append(self.take())
        self.take(")")
        field_name = args[0] if args else None
        if field_name is not None and not FIELD_NAME.fullmatch(field_name):
            raise ConditionError(f"{field_name!r} is not a field name")
        if function == "count" and len(args) > 1:
            raise ConditionError("count takes no field or one field")
        if function == "percentile":
            if len(args) != 2:
                raise ConditionError("percentile takes a field and a percentile")
            if not 0 < _number(args[1]) <= 100:
                raise ConditionError("percentile is greater than 0 and at most 100")
        elif function != "count" and len(args) != 1:
            raise ConditionError(f"{function} takes one field")
        parts = [function, field_name or ""]
        if function == "percentile":
            parts.append(args[1])
        series_id = "-".join(parts)
        if not any(entry["id"] == series_id for entry in self.series):
            entry: dict[str, Any] = {"id": series_id, "type": function}
            if field_name:
                entry["field"] = field_name
            if function == "percentile":
                entry["percentile"] = float(_number(args[1]))
            self.series.append(entry)
        return series_id

    def primary(self) -> dict[str, Any]:
        if self.peek() == "(":
            self.take("(")
            self.nest()
            node = self.or_expr()
            self.take(")")
            self.depth -= 1
            return node
        ref = self.call()
        op = self.take()
        if op not in OPERATORS:
            raise ConditionError(f"{op!r} is not a comparison")
        value = _number(self.take())
        return {
            "expr": op,
            "left": {"expr": "number-ref", "ref": ref},
            "right": {"expr": "number", "value": value},
        }

    def not_expr(self) -> dict[str, Any]:
        if self.peek() == "NOT":
            self.take("NOT")
            self.nest()
            node = {"expr": "!", "left": self.not_expr()}
            self.depth -= 1
            return node
        return self.primary()

    def and_expr(self) -> dict[str, Any]:
        node = self.not_expr()
        while self.peek() == "AND":
            self.take("AND")
            node = {"expr": "&&", "left": node, "right": self.not_expr()}
        return node

    def or_expr(self) -> dict[str, Any]:
        node = self.and_expr()
        while self.peek() == "OR":
            self.take("OR")
            node = {"expr": "||", "left": node, "right": self.and_expr()}
        return node


def parse_condition(text: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """``(condition tree, series)`` for *text* (graylog-1.0, Condition grammar).

    One series per distinct call, in order of first appearance. Raises
    :class:`ConditionError`.
    """
    tokens = _tokens(text)
    if not tokens:
        raise ConditionError("the condition is empty")
    parser = _ConditionParser(tokens)
    tree = parser.or_expr()
    if parser.index != len(tokens):
        raise ConditionError(f"unexpected {tokens[parser.index]!r}")
    return tree, parser.series


# --- event fields ----------------------------------------------------------------------------


def event_field_kind(value: Any) -> str | None:
    """``field``, ``template`` or ``lookup`` for a valid event field value, else ``None``."""
    if isinstance(value, str):
        if "${" in value:
            return "template"
        return "field" if FIELD_NAME.fullmatch(value) else None
    if isinstance(value, Mapping) and set(value) == {"template"}:
        template = value["template"]
        return "template" if isinstance(template, str) and template.strip() else None
    if isinstance(value, Mapping) and set(value) == {"lookup"}:
        lookup = value["lookup"]
        if (
            isinstance(lookup, Mapping)
            and set(lookup) == {"table", "key_field"}
            and all(isinstance(lookup[key], str) and lookup[key].strip() for key in lookup)
        ):
            return "lookup"
    return None


# --- the block -------------------------------------------------------------------------------


def _schedule_findings(schedule: Any) -> list[Finding]:
    if not isinstance(schedule, Mapping):
        return [Finding("graylog_schedule", ("schedule",), "schedule is a map")]
    found: list[Finding] = []
    every, cron = schedule.get("every"), schedule.get("cron")
    if every is not None and cron is not None:
        found.append(Finding("graylog_schedule", ("schedule",), "every and cron are exclusive"))
    for key in ("every", "window"):
        value = schedule.get(key)
        if value is not None and not _positive_duration(value):
            found.append(
                Finding(
                    "graylog_schedule",
                    ("schedule", key),
                    f"{key} is a duration greater than zero (5m, 1h10m, PT15M)",
                )
            )
    if cron is not None:
        if not cron_ok(cron):
            found.append(
                Finding(
                    "graylog_schedule",
                    ("schedule", "cron"),
                    "cron is a Quartz expression of 6 or 7 fields, with ? in day of month or "
                    "day of week (0 */5 * * * ?)",
                )
            )
        if schedule.get("window") is None:
            found.append(
                Finding("graylog_schedule", ("schedule", "window"), "window is required with cron")
            )
    timezone = schedule.get("timezone")
    if timezone is not None and not timezone_ok(timezone):
        found.append(
            Finding(
                "graylog_schedule",
                ("schedule", "timezone"),
                f"{timezone!r} is not an IANA time zone (UTC, Europe/Paris)",
            )
        )
    return found


def _aggregation_findings(aggregation: Any) -> list[Finding]:
    if not isinstance(aggregation, Mapping) or not isinstance(aggregation.get("condition"), str):
        return [Finding("graylog_aggregation", ("aggregation",), "aggregation needs a condition")]
    found: list[Finding] = []
    group_by = aggregation.get("group_by")
    if not list_ok(group_by):
        found.append(
            Finding(
                "graylog_list_shape",
                ("aggregation", "group_by"),
                "group_by is a string or a list of distinct, non-blank strings",
            )
        )
    else:
        bad = [item for item in as_list(group_by) if not FIELD_NAME.fullmatch(item)]
        if bad:
            found.append(
                Finding(
                    "graylog_field_name",
                    ("aggregation", "group_by"),
                    f"not field names ([A-Za-z0-9_.@-]+): {', '.join(bad)}",
                )
            )
    try:
        parse_condition(aggregation["condition"])
    except ConditionError as exc:
        found.append(Finding("graylog_aggregation", ("aggregation", "condition"), str(exc)))
    return found


def block_findings(block: Mapping[str, Any]) -> list[Finding]:
    """Every graylog-1.0 constraint finding of *block*, as authored, at its path.

    At the block's root a null is the key left out, as for every optional key.
    """
    raw = {key: value for key, value in block.items() if value is not None}
    found: list[Finding] = []
    query = raw.get("query")
    if not isinstance(query, str) or not query.strip():
        found.append(Finding("graylog_query_blank", ("query",)))
    for key in LIST_FIELDS:
        if not list_ok(raw.get(key)):
            found.append(
                Finding(
                    "graylog_list_shape",
                    (key,),
                    f"{key} is a string or a list of distinct, non-blank strings",
                )
            )
    if "schedule" in raw:
        found.extend(_schedule_findings(raw["schedule"]))
    aggregation = raw.get("aggregation")
    limit = raw.get("event_limit")
    if limit is not None and (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= EVENT_LIMIT_MAX
        or aggregation is not None
    ):
        message = (
            "event_limit is for filters: an aggregation creates one event per group"
            if aggregation is not None and isinstance(limit, int)
            else None
        )
        found.append(Finding("graylog_event_limit", ("event_limit",), message))
    if aggregation is not None:
        found.extend(_aggregation_findings(aggregation))
    fields = raw.get("event_fields")
    names: set[str] = set()
    if fields is not None:
        if not isinstance(fields, Mapping):
            found.append(Finding("graylog_event_field", ("event_fields",), "event_fields is a map"))
        else:
            for name, value in fields.items():
                path = ("event_fields", str(name))
                if not isinstance(name, str) or not FIELD_NAME.fullmatch(name):
                    found.append(
                        Finding(
                            "graylog_event_field",
                            path,
                            f"{name!r} is not a field name ([A-Za-z0-9_.@-]+)",
                        )
                    )
                elif event_field_kind(value) is None:
                    found.append(Finding("graylog_event_field", path))
                else:
                    names.add(name)
    key = raw.get("event_key")
    if key is not None and list_ok(key):
        missing = [item for item in as_list(key) if item not in names]
        if missing:
            found.append(
                Finding(
                    "graylog_event_key",
                    ("event_key",),
                    f"not event_fields names: {', '.join(missing)}",
                )
            )
    priority = raw.get("priority")
    if priority is not None and priority not in PRIORITIES:
        found.append(
            Finding(
                "graylog_priority",
                ("priority",),
                f"{priority!r} is not one of {', '.join(PRIORITIES)}",
            )
        )
    return found
