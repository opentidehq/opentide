"""Assemble an opentide rule's Google SecOps block into a YARA-L rule (google-secops-1.0).

The author writes the rule's sections (``events``, ``match``, ``outcome``,
``condition``, ``options``, ``setup``, ``export``); this module derives the
rest from the opentide rule: the rule name, the ``meta`` section (author,
description, severity, priority, ATT&CK techniques, the opentide
uuid and version, then the block's own meta) and the run state a status
strategy deploys. :func:`assemble` writes the text deploy sends, and records
the line of each section label so a position Google reports in the assembled
text can be put back on its key in the YAML (:meth:`AssembledRule.locate`).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import structlog

from opentide.models.deployment_enums import StatusStrategy
from opentide.models.platform import GoogleSecopsConfig
from opentide.models.rule import DetectionRule
from opentide.platforms.google_secops.checks import duration_seconds
from opentide.platforms.google_secops.yaral import (
    KEYWORDS,
    SECTION_KEYS,
    render_match,
    render_options,
    section_lines,
)

logger = structlog.get_logger(__name__)

PLATFORM = "google_secops"

#: ``response.alert_severity`` → meta ``severity`` (google-secops-1.0, Severity).
ALERT_SEVERITY: dict[str, str] = {
    "informational": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
DEFAULT_SEVERITY = "Medium"

_NOT_NAME = re.compile(r"[^a-z0-9]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
INDENT = "    "


class GoogleSecopsCompileError(ValueError):
    """A block deploy cannot assemble: it has no ``events`` or no ``condition``."""


def block_of(rule: DetectionRule) -> GoogleSecopsConfig:
    """*rule*'s ``google_secops`` block; the planner sends only rules that have one."""
    block = rule.platform_configs().google_secops
    if block is None:
        raise GoogleSecopsCompileError(f"rule {rule.name!r} has no google_secops block")
    return block


# --- derivations -------------------------------------------------------------------


def rule_name(rule_title: str, block_name: str | None, uuid: str) -> str:
    """The YARA-L rule name (google-secops-1.0, Rule name)."""
    if block_name:
        return block_name
    name = _NOT_NAME.sub("_", rule_title.lower()).strip("_")
    if not name:
        return "opentide_" + uuid.replace("-", "_")
    # A leading digit or a YARA-L keyword (a rule titled "Any") is not a rule name.
    return "r_" + name if name[0].isdigit() or name in KEYWORDS else name


def severity(rule: DetectionRule, block: GoogleSecopsConfig) -> str:
    """The block ``severity``, else ``response.alert_severity`` mapped, else ``Medium``."""
    if block.severity:
        return block.severity
    response = rule.response
    if response is None or "alert_severity" not in response.model_fields_set:
        return DEFAULT_SEVERITY
    return ALERT_SEVERITY.get(str(response.alert_severity).strip().lower(), DEFAULT_SEVERITY)


def techniques(rule: DetectionRule) -> list[str]:
    """The rule's techniques and those it inherits through ``detection_model``, sorted."""
    from opentide.generation.framework import get_type, techniques_resolver

    found: list[str] = [str(item) for item in (rule.techniques or [])]
    uuid = str(rule.metadata.uuid) if rule.metadata else ""
    if rule.detection_model and uuid and get_type(uuid, mute=True) is not None:
        try:
            found.extend(str(item) for item in techniques_resolver(uuid) or [])
        except (KeyError, TypeError, AttributeError) as exc:
            # An index without the parent: the rule's own techniques still apply.
            logger.debug("google_secops_inherited_techniques_unresolved", error=str(exc))
    return sorted(set(found))


def meta_value(text: str) -> str:
    """*text* as a YARA-L double-quoted string: ``\\`` and ``"`` escaped, controls as spaces."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + _CONTROL.sub(" ", escaped) + '"'


def meta_entries(rule: DetectionRule, block: GoogleSecopsConfig) -> list[tuple[str, str]]:
    """The ``meta`` section, in order (google-secops-1.0, Meta)."""
    authors: list[str] = []
    for author in [rule.metadata.author, *(block.contributors or [])]:
        if author and author not in authors:
            authors.append(author)
    level = severity(rule, block)
    entries = [
        ("author", ", ".join(authors)),
        ("description", " ".join(str(rule.description or "").split())),
        ("severity", level),
        ("priority", block.priority or level),
    ]
    # ``technique`` only: Google's coverage matrix reads it as a comma-separated list and
    # places each technique under its tactics; no list form of ``tactic`` is documented.
    technique_ids = techniques(rule)
    if technique_ids:
        entries.append(("technique", ",".join(technique_ids)))
    entries.append(("opentide_uuid", str(rule.metadata.uuid)))
    entries.append(("opentide_version", str(rule.metadata.version)))
    entries.extend((str(key), str(value)) for key, value in (block.meta or {}).items())
    return entries


# --- the assembled rule ------------------------------------------------------------


@dataclass(frozen=True)
class SectionPlace:
    """Where a section's content starts in the assembled text."""

    key: str
    #: 1-based line of the section's label (``  events:``).
    label_line: int
    #: Lines of content written under the label.
    lines: int
    #: Leading blank lines of the section's text that were not written.
    dropped: int


@dataclass(frozen=True)
class Location:
    """A position in the assembled text, put back on the block's YAML."""

    #: ``None``: the generated header or meta, or no position at all.
    key: str | None
    #: 1-based line and column inside the section's text; ``None`` for ``match`` and ``options``.
    line: int | None = None
    column: int | None = None

    @property
    def field_path(self) -> tuple[str, ...]:
        """The finding's path in the rule: the section key, else the block."""
        base = ("configurations", PLATFORM)
        return base if self.key is None else (*base, self.key)

    def describe(self) -> str:
        where = ".".join(self.field_path)
        if self.line is None:
            return where
        where = f"{where} line {self.line}"
        return f"{where}, column {self.column}" if self.column is not None else where


@dataclass(frozen=True)
class AssembledRule:
    """The YARA-L text deploy sends for one block, and where each section went."""

    name: str
    text: str
    sections: tuple[SectionPlace, ...] = field(default_factory=tuple)

    def label_line(self, key: str) -> int | None:
        return next((item.label_line for item in self.sections if item.key == key), None)

    def locate(self, line: int | None, column: int | None = None) -> Location:
        """The section key and its own line and column of a 1-based position in :attr:`text`."""
        if line is None:
            return Location(None)
        for place in self.sections:
            if place.label_line < line <= place.label_line + place.lines:
                if place.key in ("match", "options"):
                    return Location(place.key)
                inner = line - place.label_line + place.dropped
                inner_column = None if column is None else max(column - len(INDENT), 1)
                return Location(place.key, inner, inner_column)
        return Location(None)


def _content_lines(block: GoogleSecopsConfig, key: str) -> tuple[list[str], int]:
    if key == "match":
        match = block.match
        if match is None:
            return [], 0
        return [render_match(match.model_dump(exclude_none=True))], 0
    if key == "options":
        options = block.options
        return (render_options(options.model_dump(exclude_none=True)) if options else []), 0
    text = getattr(block, key)
    if not isinstance(text, str):
        return [], 0
    return section_lines(text)


def assemble(rule: DetectionRule, block: GoogleSecopsConfig | None = None) -> AssembledRule:
    """The YARA-L rule deploy sends for *rule* (google-secops-1.0, Assembled rule)."""
    block = block if block is not None else block_of(rule)
    missing = [key for key in ("events", "condition") if not (getattr(block, key) or "").strip()]
    if missing:
        raise GoogleSecopsCompileError(
            f"rule {rule.name!r}: configurations.google_secops has no {' and no '.join(missing)}"
        )
    name = rule_name(rule.name, block.name or None, str(rule.metadata.uuid))
    lines = [f"rule {name} {{", "  meta:"]
    lines += [f"{INDENT}{key} = {meta_value(value)}" for key, value in meta_entries(rule, block)]
    places: list[SectionPlace] = []
    for key in SECTION_KEYS:
        content, dropped = _content_lines(block, key)
        if not content:
            continue
        lines += ["", f"  {key}:"]
        places.append(SectionPlace(key, len(lines), len(content), dropped))
        lines += [f"{INDENT}{line}" if line.strip() else "" for line in content]
    lines.append("}")
    return AssembledRule(name=name, text="\n".join(lines) + "\n", sections=tuple(places))


# --- run state ---------------------------------------------------------------------


def schedule_customizations(block: GoogleSecopsConfig) -> dict[str, Any] | None:
    """``scheduleCustomizations`` for the block's ``schedule``, or ``None``."""
    schedule = block.schedule
    if schedule is None:
        return None
    custom: dict[str, Any] = {}
    if schedule.ensure_enrichment_completeness is not None:
        custom["ensureEnrichmentCompleteness"] = schedule.ensure_enrichment_completeness
    if schedule.late_arriving_data_adjustment is not None:
        seconds = duration_seconds(schedule.late_arriving_data_adjustment)
        if seconds is not None:
            custom["lateArrivingDataAdjustment"] = f"{seconds}s"
    return custom


def _settled_schedule(custom: object) -> tuple[bool, float]:
    """A ``scheduleCustomizations`` as Google stores it: an absent boolean is ``false``, an
    absent or zero adjustment ``0``, and a ``Duration`` in seconds (``"1800.000s"`` is 1800)."""
    from opentide.platforms.google_secops.client import duration_seconds as protobuf_seconds

    if not isinstance(custom, Mapping):
        return False, 0.0
    seconds = protobuf_seconds(custom.get("lateArrivingDataAdjustment"))
    return bool(custom.get("ensureEnrichmentCompleteness", False)), seconds or 0.0


#: ``RuleDeployment`` fields deploy sets, in ``updateMask`` order.
_RUN_STATE_FIELDS = ("enabled", "alerting", "runFrequency")


@dataclass(frozen=True)
class RunState:
    """A ``RuleDeployment`` update: its ``updateMask`` and body."""

    mask: str
    body: Mapping[str, Any]

    def changes(self, remote: Mapping[str, Any]) -> RunState | None:
        """The part of this update *remote* (a ``RuleDeployment``) does not hold yet, or ``None``.

        Google leaves a false boolean out of its answer. ``runFrequency`` carries
        ``scheduleCustomizations``: the schedule is compared as Google stores it,
        and a block with no ``schedule`` wants none, so one left on the remote
        rule is cleared by sending ``runFrequency`` alone.
        """
        changed: list[str] = []
        for key in _RUN_STATE_FIELDS:
            if key not in self.body:
                continue
            value = self.body[key]
            if key == "runFrequency":
                wanted = _settled_schedule(self.body.get("scheduleCustomizations"))
                current = _settled_schedule(remote.get("scheduleCustomizations"))
                if remote.get(key) != value or wanted != current:
                    changed.append(key)
            elif bool(remote.get(key, False)) != value:
                changed.append(key)
        if not changed:
            return None
        body = {key: self.body[key] for key in changed}
        if "runFrequency" in changed and "scheduleCustomizations" in self.body:
            body["scheduleCustomizations"] = self.body["scheduleCustomizations"]
        return RunState(",".join(changed), body)

    def differs_from(self, remote: Mapping[str, Any]) -> bool:
        """Whether *remote* holds another value for a field this update sends."""
        return self.changes(remote) is not None


DISABLED = RunState("enabled,alerting", {"enabled": False, "alerting": False})


def run_state(block: GoogleSecopsConfig, strategy: StatusStrategy) -> RunState:
    """The deployment update for *strategy* (google-secops-1.0, Run state by strategy).

    ``runFrequency`` is sent only when the block names one: without it Google
    keeps the rule's frequency, or gives a new rule its default, and never moves
    a legacy schedule, which Google cannot move back.
    """
    if strategy in (StatusStrategy.DISABLEMENT, StatusStrategy.DELETION):
        return DISABLED
    alerting = (
        block.alerting if block.alerting is not None else strategy is not StatusStrategy.PREVIEW
    )
    body: dict[str, Any] = {"enabled": True, "alerting": alerting}
    if block.run_frequency is None:
        return RunState("enabled,alerting", body)
    body["runFrequency"] = block.run_frequency
    custom = schedule_customizations(block)
    if custom is not None:
        body["scheduleCustomizations"] = custom
    return RunState("enabled,alerting,runFrequency", body)


def instance_resource(project: str, location: str, instance: str) -> str:
    return f"projects/{project}/locations/{location}/instances/{instance}"


def default_endpoint(location: str) -> str:
    return f"https://{location}-chronicle.googleapis.com"
