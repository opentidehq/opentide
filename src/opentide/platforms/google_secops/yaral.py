"""The parts of YARA-L 2.0 opentide checks without a parser (yara-l-1.0).

A ``configurations.google_secops`` block carries a rule's sections as keys
(``YaraLSections``): ``setup``, ``events``, ``outcome``, ``condition`` and
``export`` as YARA-L text, ``match`` (``YaraLMatch``) and ``options``
(``YaraLOptions``) as YAML objects. This module checks the structural codes of
the language spec that need no parser (``yaral_section_missing``,
``yaral_section_empty``, ``yaral_section_header``, ``yaral_match_shape``,
``yaral_match_window``, ``yaral_option``) and renders ``match`` and ``options``
as deploy writes them. Everything else in the language (scope, UDM fields,
functions, condition shape) is the analysis engine's.

The scanner keeps line numbers and columns: a label or a keyword inside a
comment or a string, raw-string or regex literal never counts.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, NamedTuple

#: Case-insensitive keywords (yara-l-1.0, Lexical structure), section names included.
KEYWORDS = frozenset(
    {
        "rule",
        "meta",
        "events",
        "match",
        "outcome",
        "condition",
        "options",
        "dedup",
        "order",
        "limit",
        "select",
        "unselect",
        "and",
        "or",
        "not",
        "nocase",
        "in",
        "regex",
        "cidr",
        "any",
        "all",
        "over",
        "by",
        "before",
        "after",
        "if",
        "of",
        "true",
        "false",
        "asc",
        "desc",
        "setup",
        "export",
        "stage",
    }
)
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

#: Every section label, rule and search (yara-l-1.0, Sections).
SECTION_LABELS = (
    "meta",
    "setup",
    "events",
    "match",
    "outcome",
    "condition",
    "options",
    "export",
    "dedup",
    "order",
    "limit",
    "select",
    "unselect",
)
#: The block's section keys, in the order deploy writes them.
SECTION_KEYS = ("setup", "events", "match", "outcome", "condition", "options", "export")
#: The section keys that hold YARA-L text.
TEXT_SECTIONS = ("setup", "events", "outcome", "condition", "export")
#: The sections a rule cannot do without.
REQUIRED_SECTIONS = ("events", "condition")
#: ``options`` keys, in the order deploy writes them.
OPTION_KEYS = ("allow_zero_values", "suppression_window")

_SECTION_LABEL = re.compile(r"^\s*(" + "|".join(SECTION_LABELS) + r")\s*:", re.IGNORECASE)
_RULE_HEADER = re.compile(r"^\s*rule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{?", re.IGNORECASE)
_VARIABLE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_WINDOW = re.compile(r"([1-9][0-9]*)([mhd])")
_MATCH_FIELDS = frozenset({"group_by", "window", "type", "pivot", "direction"})
#: ``match.type`` and the keyword it renders.
MATCH_TYPES = {"hop": "over", "tumbling": "by", "sliding": "over"}
#: The longest window of each kind under the rule profile, in minutes (yara-l-1.0, ``match``).
_RULE_WINDOW_MAX = {"over": 14 * 1440, "by": 72 * 60}
_EVENT_VARIABLE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*\.")

EMPTY_HINT = (
    "; a plain YAML scalar that starts with # is a YAML comment, so it loads as null: "
    "write the text as a block scalar (|)"
)


class Finding(NamedTuple):
    """A code, the path it is reported at relative to the block, and its message."""

    code: str
    path: tuple[str, ...]
    message: str


def code_lines(text: str, *, blank_literals: bool = True) -> list[str]:
    """*text*'s lines with comments and string, raw-string and regex contents blanked.

    Lengths are kept, so a column in a blanked line is the column in *text*. A
    ``/`` starts a regex literal only where an operand is expected, so division
    is left alone. With *blank_literals* false, only comments are blanked.
    """
    out: list[str] = []
    in_block = False
    for line in normalise_newlines(text).split("\n"):
        buf: list[str] = []
        index = 0
        quote: str | None = None
        while index < len(line):
            char = line[index]
            if in_block:
                if line.startswith("*/", index):
                    in_block = False
                    buf.append("  ")
                    index += 2
                    continue
                buf.append(" ")
            elif quote is not None:
                if quote != "`" and char == "\\" and index + 1 < len(line):
                    buf.append("  " if blank_literals else line[index : index + 2])
                    index += 2
                    continue
                if char == quote:
                    quote = None
                    buf.append(char)
                else:
                    buf.append(" " if blank_literals else char)
            elif line.startswith("//", index):
                buf.append(" " * (len(line) - index))
                break
            elif line.startswith("/*", index):
                in_block = True
                buf.append("  ")
                index += 2
                continue
            elif char in '"`' or (char == "/" and _operand_expected(buf)):
                quote = char
                buf.append(char)
            else:
                buf.append(char)
            index += 1
        out.append("".join(buf))
    return out


def _operand_expected(buf: list[str]) -> bool:
    """Whether a ``/`` here starts a regex literal rather than dividing."""
    before = "".join(buf).rstrip()
    if not before:
        return True
    if before[-1] in "=!<>(,[":
        return True
    word = re.search(r"[A-Za-z_]+$", before)
    return word is not None and word.group(0).lower() in {"and", "or", "not", "in", "regex"}


def normalise_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def section_lines(text: str) -> tuple[list[str], int]:
    """A text section's lines as deploy writes them, and how many leading lines it dropped.

    Line endings become ``\\n``; leading and trailing blank lines go. Nothing
    else changes: not a character of an expression, a comment or a literal.
    """
    lines = normalise_newlines(text).split("\n")
    dropped = 0
    while lines and not lines[0].strip():
        lines.pop(0)
        dropped += 1
    while lines and not lines[-1].strip():
        lines.pop()
    return lines, dropped


def event_variables(events: object) -> list[str]:
    """The event variables ``events`` uses (``$e`` of ``$e.metadata…``), in order, each once."""
    if not isinstance(events, str):
        return []
    found: dict[str, None] = {}
    for line in code_lines(events):
        for match in _EVENT_VARIABLE.finditer(line):
            found.setdefault(match.group(1), None)
    return list(found)


def is_identifier(value: object) -> bool:
    """A YARA-L identifier that is not a keyword."""
    return (
        isinstance(value, str)
        and IDENTIFIER.fullmatch(value) is not None
        and value.lower() not in KEYWORDS
    )


# --- YaraLSections -----------------------------------------------------------------


def section_findings(block: Mapping[str, Any]) -> list[Finding]:
    """The structural codes of the block's sections (yara-l-1.0, YaraLSections)."""
    found = [
        Finding(
            "yaral_section_missing",
            (key,),
            f"a rule needs a {key} section: write it under configurations.google_secops.{key}",
        )
        for key in REQUIRED_SECTIONS
        if key not in block
    ]
    for key in TEXT_SECTIONS:
        if key not in block:
            continue
        text = block[key]
        if text is None or (isinstance(text, str) and not text.strip()):
            found.append(Finding("yaral_section_empty", (key,), f"{key} has no text{EMPTY_HINT}"))
            continue
        if not isinstance(text, str):
            found.append(
                Finding(
                    "yaral_section_empty",
                    (key,),
                    f"{key} is YARA-L text, not a YAML {_yaml_kind(text)}: write it as a block "
                    "scalar (|)",
                )
            )
            continue
        header = section_header_line(text)
        if header is not None:
            found.append(
                Finding(
                    "yaral_section_header",
                    (key,),
                    f"{key} holds a section label, a rule header or a rule's braces (line "
                    f"{header}); deploy writes the header and meta, and each section is its "
                    "own key",
                )
            )
    if "match" in block:
        found.extend(match_findings(block["match"]))
    if "options" in block:
        found.extend(options_findings(block["options"]))
    return found


def section_header_line(text: str) -> int | None:
    """The 1-based line of *text* holding a section label, a ``rule`` header or a lone brace."""
    for number, line in enumerate(code_lines(text), start=1):
        if _RULE_HEADER.match(line) or _SECTION_LABEL.match(line) or line.strip() in ("{", "}"):
            return number
    return None


def _yaml_kind(value: object) -> str:
    if isinstance(value, Mapping):
        return "mapping"
    if isinstance(value, list):
        return "list"
    return type(value).__name__


# --- YaraLMatch --------------------------------------------------------------------


def window_minutes(window: object) -> int | None:
    """A ``<n>m``, ``<n>h`` or ``<n>d`` duration in minutes, or ``None``."""
    found = _WINDOW.fullmatch(window) if isinstance(window, str) else None
    if found is None:
        return None
    return int(found.group(1)) * {"m": 1, "h": 60, "d": 1440}[found.group(2)]


def match_findings(match: Any) -> list[Finding]:
    """``yaral_match_shape`` and ``yaral_match_window`` (yara-l-1.0, YaraLMatch)."""
    if not isinstance(match, Mapping):
        return [
            Finding(
                "yaral_match_shape",
                ("match",),
                "match is an object with group_by and window",
            )
        ]
    # An unset field (YAML null, or a dumped model's None) is absent.
    match = {key: value for key, value in match.items() if value is not None}
    found: list[Finding] = []
    unknown = sorted(str(key) for key in match if key not in _MATCH_FIELDS)
    if unknown:
        found.append(
            Finding(
                "yaral_match_shape",
                ("match", unknown[0]),
                f"unknown match key(s) {', '.join(unknown)}: match takes group_by, window, "
                "type, pivot and direction",
            )
        )
    group_by = match.get("group_by")
    if (
        not isinstance(group_by, list)
        or not group_by
        or not all(isinstance(name, str) and _VARIABLE.fullmatch(name) for name in group_by)
        or len(set(group_by)) != len(group_by)
    ):
        found.append(
            Finding(
                "yaral_match_shape",
                ("match", "group_by"),
                "group_by is a non-empty list of distinct placeholders, each $name",
            )
        )
    kind = match.get("type", "hop")
    if not isinstance(kind, str) or kind not in MATCH_TYPES:
        found.append(
            Finding(
                "yaral_match_shape",
                ("match", "type"),
                f"type {kind!r} is not hop, tumbling or sliding",
            )
        )
    pivot, direction = match.get("pivot"), match.get("direction")
    if kind == "sliding":
        if not (isinstance(pivot, str) and _VARIABLE.fullmatch(pivot)) or direction not in (
            "before",
            "after",
        ):
            found.append(
                Finding(
                    "yaral_match_shape",
                    ("match",),
                    "a sliding window needs pivot (the $event it is anchored on) and "
                    "direction (before or after)",
                )
            )
    elif pivot is not None or direction is not None:
        found.append(
            Finding(
                "yaral_match_shape",
                ("match", "pivot" if pivot is not None else "direction"),
                "pivot and direction belong to a sliding window (type: sliding)",
            )
        )
    window = match.get("window")
    minutes = window_minutes(window)
    if minutes is None:
        found.append(
            Finding(
                "yaral_match_window",
                ("match", "window"),
                f"window {window!r} is not a duration in m, h or d (10m, 1h, 2d)",
            )
        )
    else:
        bound_key = "by" if kind == "tumbling" else "over"
        if minutes > _RULE_WINDOW_MAX[bound_key]:
            bound = "72h" if kind == "tumbling" else "14d"
            label = kind if isinstance(kind, str) and kind in MATCH_TYPES else "hop"
            found.append(
                Finding(
                    "yaral_match_window",
                    ("match", "window"),
                    f"window {window}: a {label} window in a rule is at most {bound}",
                )
            )
    return found


def render_match(match: Mapping[str, Any]) -> str:
    """The ``match:`` line deploy writes from a ``YaraLMatch``."""
    kind = str(match.get("type") or "hop")
    text = f"{', '.join(match['group_by'])} {MATCH_TYPES[kind]} {match['window']}"
    if kind == "sliding":
        return f"{text} {match['direction']} {match['pivot']}"
    return text


# --- YaraLOptions ------------------------------------------------------------------


def options_findings(options: Any) -> list[Finding]:
    """``yaral_option`` (yara-l-1.0, YaraLOptions)."""
    if not isinstance(options, Mapping):
        return [
            Finding(
                "yaral_option",
                ("options",),
                "options is an object with allow_zero_values and suppression_window",
            )
        ]
    found: list[Finding] = []
    for key, value in options.items():
        if value is None:
            continue  # unset
        if key == "allow_zero_values" and isinstance(value, bool):
            continue
        if key == "suppression_window" and window_minutes(value) is not None:
            continue
        if key in OPTION_KEYS:
            expected = "true or false" if key == "allow_zero_values" else "a duration (5m, 1h, 1d)"
            message = f"options.{key} is {expected}, not {value!r}"
        else:
            message = (
                f"{key!r} is not an option: options takes allow_zero_values and suppression_window"
            )
        found.append(Finding("yaral_option", ("options", str(key)), message))
    return found


def render_options(options: Mapping[str, Any]) -> list[str]:
    """The ``options:`` lines deploy writes: only the keys set, in :data:`OPTION_KEYS` order."""
    lines: list[str] = []
    for key in OPTION_KEYS:
        if key not in options or options[key] is None:
            continue
        value = options[key]
        lines.append(f"{key} = {str(value).lower() if isinstance(value, bool) else value}")
    return lines
