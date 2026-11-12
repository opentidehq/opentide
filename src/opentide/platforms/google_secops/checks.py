"""Static checks of a ``configurations.google_secops`` block (google-secops-1.0).

:func:`block_findings` reads the block as authored and returns every
constraint code of the spec (``google_secops_*``) and the structural YARA-L
codes of its sections (:mod:`~opentide.platforms.google_secops.yaral`), each at
the ``field_path`` the spec fixes for it, relative to the block. The model's
before-validator raises them all at once, before the field types run, so
``opentide validate`` and the editor name the same finding.

The workspace check ``google_secops_name_duplicate`` and the YAML alias check
``yaral_section_alias`` need more than the block: they are in
:mod:`opentide.validation.google_secops`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from opentide.platforms.google_secops.yaral import (
    KEYWORDS,
    Finding,
    is_identifier,
    section_findings,
)

#: Severity and priority values (google-secops-1.0, Constraints).
SEVERITIES = ("Info", "Low", "Medium", "High", "Critical")
#: Run frequencies opentide accepts. Deploy sends one only when the block names it.
RUN_FREQUENCIES = ("LIVE", "LIVE_CUSTOMIZABLE", "HOURLY_CUSTOMIZABLE", "DAILY")
#: The run frequencies that take schedule customizations.
CUSTOMIZABLE = frozenset({"LIVE_CUSTOMIZABLE", "HOURLY_CUSTOMIZABLE"})
#: The meta keys deploy writes, in order (google-secops-1.0, Meta).
DERIVED_META = (
    "author",
    "description",
    "severity",
    "priority",
    "technique",
    "opentide_uuid",
    "opentide_version",
)
_DURATION = re.compile(r"([1-9][0-9]*)([smhd])")

#: Every code :func:`block_findings` reports. Pydantic raises each as the error's type.
CONSTRAINT_CODES = frozenset(
    {
        "google_secops_rule_name",
        "google_secops_severity",
        "google_secops_run_frequency",
        "google_secops_schedule",
        "google_secops_meta_key",
        "yaral_section_missing",
        "yaral_section_empty",
        "yaral_section_header",
        "yaral_match_shape",
        "yaral_match_window",
        "yaral_option",
    }
)


def duration_seconds(value: object) -> int | None:
    """A positive ``<n>s``, ``<n>m``, ``<n>h`` or ``<n>d`` duration in seconds, or ``None``."""
    found = _DURATION.fullmatch(value) if isinstance(value, str) else None
    if found is None:
        return None
    return int(found.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[found.group(2)]


def _schedule_findings(raw: Mapping[str, Any]) -> list[Finding]:
    schedule = raw.get("schedule")
    if schedule is None:
        return []
    found: list[Finding] = []
    frequency = raw.get("run_frequency")
    if not isinstance(frequency, str) or frequency not in CUSTOMIZABLE:
        found.append(
            Finding(
                "google_secops_schedule",
                ("schedule",),
                "schedule customizes LIVE_CUSTOMIZABLE and HOURLY_CUSTOMIZABLE rules only: "
                "set run_frequency to one of them, or remove schedule",
            )
        )
    if isinstance(schedule, Mapping):
        adjustment = schedule.get("late_arriving_data_adjustment")
        if adjustment is not None and duration_seconds(adjustment) is None:
            found.append(
                Finding(
                    "google_secops_schedule",
                    ("schedule", "late_arriving_data_adjustment"),
                    f"late_arriving_data_adjustment {adjustment!r} is not a positive duration "
                    "in s, m, h or d (30m, 2h)",
                )
            )
    return found


def _meta_findings(meta: Any) -> list[Finding]:
    if not isinstance(meta, Mapping):
        return []  # the field type reports it
    found: list[Finding] = []
    for key, value in meta.items():
        if not is_identifier(key):
            reason = (
                "a YARA-L keyword"
                if isinstance(key, str) and key.lower() in KEYWORDS
                else "not an identifier ([A-Za-z_][A-Za-z0-9_]*)"
            )
        elif key in DERIVED_META:
            reason = "a key deploy writes itself"
        elif not isinstance(value, str):
            reason = f"set to a {type(value).__name__}: a meta value is a string (quote it)"
        else:
            continue
        found.append(
            Finding(
                "google_secops_meta_key",
                ("meta", str(key)),
                f"meta key {key!r} is {reason}",
            )
        )
    return found


def block_findings(block: Mapping[str, Any]) -> list[Finding]:
    """Every constraint and structural YARA-L finding of *block*, as authored."""
    found: list[Finding] = []
    name = block.get("name")
    if isinstance(name, str) and name and not is_identifier(name):
        found.append(
            Finding(
                "google_secops_rule_name",
                ("name",),
                f"name {name!r} is not a YARA-L rule name: an identifier "
                "([A-Za-z_][A-Za-z0-9_]*) that is not a keyword",
            )
        )
    for key in ("severity", "priority"):
        value = block.get(key)
        if value is not None and (not isinstance(value, str) or value not in SEVERITIES):
            found.append(
                Finding(
                    "google_secops_severity",
                    (key,),
                    f"{key} {value!r} is not Info, Low, Medium, High or Critical",
                )
            )
    frequency = block.get("run_frequency")
    if frequency is not None and (
        not isinstance(frequency, str) or frequency not in RUN_FREQUENCIES
    ):
        legacy = " (Google's legacy HOURLY is refused)" if frequency == "HOURLY" else ""
        found.append(
            Finding(
                "google_secops_run_frequency",
                ("run_frequency",),
                f"run_frequency {frequency!r} is not LIVE, LIVE_CUSTOMIZABLE, "
                f"HOURLY_CUSTOMIZABLE or DAILY{legacy}",
            )
        )
    found.extend(_schedule_findings(block))
    found.extend(_meta_findings(block.get("meta")))
    if "query" in block:
        found.append(
            Finding(
                "extra_forbidden",
                ("query",),
                "query is not a google_secops key: write the rule as its sections (events, "
                "match, outcome, condition, options)",
            )
        )
    found.extend(section_findings(block))
    return found


def block_codes(block: Mapping[str, Any]) -> set[str]:
    """The codes of :func:`block_findings`."""
    return {finding.code for finding in block_findings(block)}
