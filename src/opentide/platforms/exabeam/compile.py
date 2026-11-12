"""Compile an opentide rule's Exabeam block into a correlation rule body (exabeam-1.0).

The author writes the sequences and the response settings; this module
derives the rest from the opentide rule: the Exabeam rule name, description
(with the ATT&CK line and the ``opentide:`` marker) and severity. The body of
``POST /correlation-rules/v2/rules`` (create) and ``PUT
/correlation-rules/v2/rules/{id}`` (update) is the same, and every update sends
all of it: ``PUT`` replaces the rule. Keys are built in the order of the
spec's Compiled body table; the goldens under ``tests/fixtures/exabeam/`` are
the exact bodies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from opentide.models.deployment_enums import StatusStrategy
from opentide.models.platform import ExabeamConfig
from opentide.models.platform_configs import (
    ExabeamEmail,
    ExabeamRecurrence,
    ExabeamSequence,
    ExabeamThreshold,
)
from opentide.models.rule import DetectionRule
from opentide.platforms.exabeam.constraints import (
    UNITS,
    delay_minutes,
    duration,
)

RULES_PATH = "/correlation-rules/v2/rules"
SEARCH_PATH = "/search/v2/events"

#: ``response.alert_severity`` → Exabeam ``severity`` (exabeam-1.0, Severity).
ALERT_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "none",
}
DEFAULT_SEVERITY = "medium"

#: ``schedule[].every`` → ``recurrenceType``.
RECURRENCE_TYPES: dict[str, str] = {
    "day": "DAILY",
    "week": "WEEKLY",
    "month": "MONTHLY",
    "days": "CUSTOM",
}

#: The window ``validate query --live`` searches: the console's "Test Last 15 mins".
LIVE_WINDOW = timedelta(minutes=15)


@dataclass(frozen=True)
class ExabeamRule:
    """What a block deploys on one tenant, after derivation."""

    uuid: str
    name: str
    body: dict[str, Any]

    @property
    def has_schedule(self) -> bool:
        return "scheduleConfig" in self.body


def block_of(rule: DetectionRule) -> ExabeamConfig:
    """The rule's Exabeam block, or an error naming the rule."""
    block = rule.platform_configs().exabeam
    if block is None:
        raise ValueError(f"Rule {rule.metadata.uuid} ({rule.name}) has no exabeam block")
    return block


def exabeam_name(rule_name: str, block_name: str | None) -> str:
    """The shared ``name``, else the opentide rule ``name``."""
    return block_name or rule_name


def derive_description(rule: DetectionRule) -> str:
    """The description, whitespace collapsed; the ATT&CK line; the ``opentide:`` marker."""
    from opentide.platforms.sysdig.compile import rule_techniques

    text = " ".join(str(rule.description or "").split())
    techniques = rule_techniques(rule)
    lines = [f"ATT&CK: {', '.join(techniques)}"] if techniques else []
    lines.append(f"opentide: {rule.metadata.uuid}")
    return text + "\n\n" + "\n".join(lines)


def derive_severity(rule: DetectionRule, block: ExabeamConfig) -> str:
    """The block ``severity``, else ``response.alert_severity``'s, else ``medium``."""
    if block.severity:
        return block.severity
    response = rule.response
    if response is None or "alert_severity" not in response.model_fields_set:
        return DEFAULT_SEVERITY
    return ALERT_SEVERITY.get(str(response.alert_severity).strip().lower(), DEFAULT_SEVERITY)


def time_unit(value: str, units: str = "mhd") -> tuple[int, str]:
    """``(time, unit)`` for a duration, the unit spelled as Exabeam takes it (``minutes``)."""
    parsed = duration(value, units)
    if parsed is None:
        raise ValueError(f"{value!r} is not a duration in {units}")
    return parsed[0], UNITS[parsed[1]]


def threshold_value(value: Any) -> str:
    """``value`` as the API takes it: a number in its shortest form, a list joined by ``,``."""

    def one(item: Any) -> str:
        if isinstance(item, float) and item.is_integer():
            return str(int(item))
        return str(item)

    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(one(item) for item in value)
    return one(value)


def _condition(sequence: ExabeamSequence) -> dict[str, Any]:
    group_by = list(sequence.group_by or [])
    threshold: ExabeamThreshold | None = sequence.threshold
    condition: dict[str, Any] = {
        "triggerOnAnyMatch": threshold is None,
        "groupByOption": bool(group_by),
        "groupBy": group_by,
    }
    if threshold is None:
        return condition
    condition["functionType"] = threshold.function
    condition["subject"] = "field" if threshold.field else "event"
    if threshold.field:
        condition["field"] = threshold.field
    condition["operator"] = threshold.operator
    condition["value"] = threshold_value(threshold.value)
    condition["time"], condition["unit"] = time_unit(threshold.within)
    return condition


def _sequence(sequence: ExabeamSequence) -> dict[str, Any]:
    entry: dict[str, Any] = {}
    if sequence.name:
        entry["name"] = sequence.name
    entry["query"] = sequence.query.strip()
    entry["condition"] = _condition(sequence)
    return entry


def _outcomes(block: ExabeamConfig, name: str) -> dict[str, Any]:
    outcome = block.outcome or "alert"
    email: ExabeamEmail | None = block.email
    outcomes: dict[str, Any] = {
        "sendAlertTriage": outcome == "alert",
        "createCase": outcome == "case",
        "sendEmail": email is not None,
    }
    if outcome == "alert":
        outcomes["alertTriage"] = {"name": name}
    if outcome == "case":
        outcomes["case"] = {"description": name}
    if email is not None:
        outcomes["email"] = {
            "recipients": list(email.recipients),
            "subject": email.subject or name,
            "attachCsv": email.attach_csv,
        }
    return outcomes


def _recurrence(recurrence: ExabeamRecurrence) -> dict[str, Any]:
    out: dict[str, Any] = {
        "recurrenceType": RECURRENCE_TYPES[recurrence.every],
        "startTime": recurrence.from_,
        "endTime": recurrence.to,
    }
    if recurrence.every == "week":
        out["daysOfWeek"] = [str(day).upper() for day in recurrence.days or []]
    elif recurrence.every == "month":
        out["daysInMonth"] = list(recurrence.days or [])
        out["lastDayOfMonth"] = bool(recurrence.last_day)
    elif recurrence.every == "days":
        out["dayFrom"] = str(recurrence.first).upper()
        out["dayTo"] = str(recurrence.last).upper()
    return out


def compile_body(
    rule: DetectionRule, strategy: StatusStrategy, *, tenant_test_mode: bool = False
) -> dict[str, Any]:
    """The create and update body of *rule* under *strategy* (exabeam-1.0, Compiled body)."""
    block = block_of(rule)
    name = exabeam_name(rule.name, block.name)
    sequences = [_sequence(sequence) for sequence in block.sequences]
    sequences_config: dict[str, Any] = {"sequences": sequences}
    if len(sequences) >= 2:
        correlation = block.correlation
        if correlation is None:
            raise ValueError(f"Rule {rule.metadata.uuid}: two or more sequences need correlation")
        time, unit = time_unit(correlation.within)
        sequences_config["commonProperties"] = {
            "groupBy": list(correlation.group_by),
            "time": time,
            "unit": unit,
        }
    sequences_config["outcomes"] = _outcomes(block, name)
    test_mode = block.test_mode if block.test_mode is not None else tenant_test_mode
    body: dict[str, Any] = {
        "name": name,
        "description": derive_description(rule),
        "severity": derive_severity(rule, block),
        "enabled": strategy is not StatusStrategy.DISABLEMENT,
        "testMode": bool(test_mode),
        "sequencesConfig": sequences_config,
    }
    suppression = block.suppression
    if suppression is not None:
        time, unit = time_unit(suppression.for_, "mhdw")
        suppress: dict[str, Any] = {
            "suppressOption": True,
            "suppressTime": time,
            "suppressUnit": unit,
        }
        if suppression.group_by:
            suppress["granularSuppressOption"] = True
            suppress["suppressGroupFields"] = list(suppression.group_by)
        body["suppressConfig"] = suppress
    else:
        body["suppressConfig"] = {"suppressOption": False}
    minutes = delay_minutes(block.delay) if block.delay else None
    body["delayConfig"] = (
        {"delay": True, "delayTimeInMinutes": minutes} if minutes else {"delay": False}
    )
    if block.schedule:
        body["scheduleConfig"] = {"recurrences": [_recurrence(item) for item in block.schedule]}
    return body


def compile_rule(
    rule: DetectionRule, strategy: StatusStrategy, setup: Any | None = None
) -> ExabeamRule:
    """What *rule* deploys under *strategy* on the tenant whose ``setup`` is given.

    Without a tenant (an offline preview), ``testMode`` falls back to ``false``
    when the block does not set it.
    """
    tenant_test_mode = bool(getattr(setup, "test_mode", False)) if setup is not None else False
    body = compile_body(rule, strategy, tenant_test_mode=tenant_test_mode)
    return ExabeamRule(uuid=str(rule.metadata.uuid), name=str(body["name"]), body=body)


def create_request(compiled: ExabeamRule) -> dict[str, Any]:
    """The create call, as the goldens hold it: method, path and body."""
    return {"method": "POST", "path": RULES_PATH, "body": compiled.body}


def update_request(compiled: ExabeamRule, rule_id: str) -> dict[str, Any]:
    """The update call: ``PUT`` with the whole body."""
    return {"method": "PUT", "path": f"{RULES_PATH}/{rule_id}", "body": compiled.body}


def _utc(moment: datetime) -> str:
    """*moment* as ``YYYY-MM-DDThh:mm:ssZ``; a naive datetime is read as UTC."""
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def search_body(
    query: str,
    *,
    start: datetime,
    end: datetime,
    limit: int,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """A ``POST /search/v2/events`` body: the query as ``filter``, every field unless named."""
    return {
        "filter": query.strip(),
        "fields": list(fields) if fields else ["*"],
        "startTime": _utc(start),
        "endTime": _utc(end),
        "limit": limit,
    }


def live_search_request(query: str, now: datetime) -> dict[str, Any]:
    """The ``--live`` filter check: one row over the 15 minutes before *now*."""
    return {
        "method": "POST",
        "path": SEARCH_PATH,
        "body": search_body(query, start=now - LIVE_WINDOW, end=now, limit=1),
    }
