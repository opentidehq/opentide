"""The Bitdefender GravityZone criteria catalogue and block checks (bitdefender-1.0).

Static validation of a ``configurations.bitdefender`` block: the constraint
codes of the spec (``bitdefender_*``) and the parser-free YARA checks of
yara-1.0 (``yara_include``, ``yara_empty_signature``, ``yara_duplicate_rule``)
under the Bitdefender profile (``bitdefender_yara_ascii``,
``bitdefender_yara_size``). :func:`block_codes` reads the block as authored, so
:class:`~opentide.models.platform.BitdefenderConfig` can report every code at
once, before the field types run.

Each code is reported at the ``field_path`` the spec fixes for it (bitdefender-1.0,
Constraints), relative to the block, so opentide and the editor name the same
finding. The catalogue (:mod:`~opentide.platforms.bitdefender.criteria`) covers
the EDR targets; a field of another target is not checked here, because the
spec makes an unknown field there a warning.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from opentide.platforms.bitdefender.criteria import ALERT_OR_OPERATION, FIELDS, ONE_RESOURCE_TARGETS
from opentide.platforms.bitdefender.criteria import Field as CatalogueField

#: Detection targets, as the API spells them (bitdefender-1.0, ``detection``).
DETECTION_TARGETS: frozenset[str] = frozenset(
    {
        "process",
        "file",
        "connection",
        "registry",
        "user connection",
        "email",
        "application",
        "key vault",
        "role",
        "policy",
        "sharing link",
        "url",
        "ssh key",
        "launch template",
        "service principal",
        "user group",
        "automation account",
        "automation account hook",
        "certificate authority",
        "api",
        "bucket",
        "jira project",
        "confluence page",
    }
)


#: A code and the path it is reported at, relative to ``configurations.bitdefender``.
Finding = tuple[str, tuple[str, ...]]

#: What each constraint code says, for the finding's message (bitdefender-1.0, Constraints).
CODE_MESSAGES: dict[str, str] = {
    "bitdefender_rule_kind": "a Bitdefender block sets exactly one of detection and yara",
    "bitdefender_target": "target is not a GravityZone detection target",
    "bitdefender_criterion_shape": (
        "a criterion has field and exactly one of is (a string or an integer), contains "
        "(a string) and any (a non-empty list of strings or integers)"
    ),
    "bitdefender_criterion_field": "the field is not one of the target's in the criteria catalogue",
    "bitdefender_criterion_relation": "the field does not take this relation",
    "bitdefender_criterion_value": "the value is not one the field accepts",
    "bitdefender_criteria_combination": "the criteria break a pairing rule of the catalogue",
    "bitdefender_action_scope": "the action is not allowed for the rule's kind and target",
    "bitdefender_targets_shape": "targets sets one of endpoint_tags and companies, non-empty",
    "bitdefender_severity": "severity is Low, Medium or High",
    "bitdefender_yara_ascii": "the YARA signature holds ASCII characters only",
    "bitdefender_yara_size": "the YARA signature is at most 30,000 characters",
    "yara_include": "the YARA signature has an include directive",
    "yara_empty_signature": "the YARA signature has no rule that is neither private nor global",
    "yara_duplicate_rule": "two YARA rules in the signature have one name",
}

#: Every constraint code :func:`block_findings` reports.
CONSTRAINT_CODES: frozenset[str] = frozenset(CODE_MESSAGES)

#: The EDR targets the catalogue lists, each with its detection fields.
TARGET_FIELDS: dict[str, frozenset[str]] = {
    target: frozenset(name for name, item in FIELDS.items() if item.target == target)
    for target in ("process", "file", "connection", "registry")
}

_CRITERIA = ("detection", "criteria")

RELATIONS: tuple[str, ...] = ("is", "contains", "any")

#: Action key → GravityZone automatic action ``type`` (bitdefender-1.0, ``actions``).
ACTION_TYPES: dict[str, int] = {
    "isolate": 1,
    "collect_investigation_package": 2,
    "sandbox": 3,
    "kill_process": 4,
    "antimalware_scan": 5,
    "quarantine": 6,
    "risk_scan": 7,
}
#: Actions that act on a process or a file: a ``process`` or ``file`` target or a
#: ``*.CreatedBy.*`` criterion, on a Basic rule.
PROCESS_ACTIONS: frozenset[str] = frozenset({"sandbox", "kill_process", "quarantine"})
#: Actions a YARA rule cannot take.
NOT_ON_YARA: frozenset[str] = frozenset({"kill_process"})

SEVERITIES: dict[str, int] = {"Low": 1, "Medium": 2, "High": 3}

#: Bitdefender profile of the YARA language (yara-1.0, Platform profiles).
YARA_MAX_CHARACTERS = 30_000

_YARA_COMMENT_OR_STRING = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"', re.DOTALL)
_YARA_INCLUDE = re.compile(r"(?m)^\s*include\b")
_YARA_RULE = re.compile(
    r"(?<![\w$.#@!])((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)"
)


def _scalar(value: Any) -> bool:
    """A string or an integer: a boolean is neither."""
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _relation(criterion: Mapping[str, Any]) -> str:
    return next(key for key in RELATIONS if key in criterion)


def _values(criterion: Mapping[str, Any]) -> list[Any]:
    relation = _relation(criterion)
    value = criterion[relation]
    return list(value) if relation == "any" else [value]


def _criterion_shape_ok(criterion: Any) -> bool:
    """``field`` and one relation: ``is`` a string or integer, ``contains`` a string,
    ``any`` a non-empty list of strings or integers."""
    if not isinstance(criterion, Mapping) or not isinstance(criterion.get("field"), str):
        return False
    relations = [key for key in RELATIONS if key in criterion]
    if len(relations) != 1 or set(criterion) - {"field", *RELATIONS}:
        return False
    value = criterion[relations[0]]
    if relations[0] == "any":
        return isinstance(value, list) and bool(value) and all(map(_scalar, value))
    if relations[0] == "contains":
        return isinstance(value, str)
    return _scalar(value)


def _value_ok(item: CatalogueField, value: Any) -> bool:
    if item.kind == "enum":
        return isinstance(value, str) and value in item.values
    if item.kind == "port":
        low, high = item.minimum or 0, item.maximum if item.maximum is not None else 65535
        return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high
    return True


def _criterion_codes(target: str, criterion: Mapping[str, Any]) -> set[str]:
    """``bitdefender_criterion_field``, ``_relation`` and ``_value`` for one criterion."""
    if target not in TARGET_FIELDS:
        return set()
    item = FIELDS.get(str(criterion["field"]))
    if item is None or item.target != target:
        return {"bitdefender_criterion_field"}
    relation = _relation(criterion)
    if relation not in item.relations or (relation == "contains" and item.kind == "hash"):
        return {"bitdefender_criterion_relation"}
    if not all(_value_ok(item, value) for value in _values(criterion)):
        return {"bitdefender_criterion_value"}
    return set()


def _sensors(criteria: list[Mapping[str, Any]]) -> set[str]:
    """The sensors the criteria need: a field's, or each enum value's."""
    sensors: set[str] = set()
    for criterion in criteria:
        item = FIELDS.get(str(criterion["field"]))
        if item is None:
            continue
        if item.kind == "enum":
            sensors.update(
                item.values.get(str(value), item.availability) for value in _values(criterion)
            )
        else:
            sensors.add(item.availability)
    return sensors - {"both"}


def _combination_ok(target: str, criteria: list[Mapping[str, Any]], alert: Any) -> bool:
    """The catalogue's pairing rules (bitdefender-1.0, ``bitdefender_criteria_combination``)."""
    fields = {str(c["field"]) for c in criteria}
    present = fields | ({"detection"} if alert else set())
    sensors = _sensors(criteria)
    if {"edr", "xdr"} <= sensors:
        return False
    for criterion in criteria:
        item = FIELDS.get(str(criterion["field"]))
        if item is None:
            continue
        if item.requires_any and not set(item.requires_any) & present:
            return False
        if item.detection_requires_any and not set(item.detection_requires_any) & present:
            return False
        if set(item.incompatible) & fields:
            return False
        for value in _values(criterion):
            if set(item.value_incompatible.get(str(value), ())) & fields:
                return False
    if target in ONE_RESOURCE_TARGETS:
        resources = {FIELDS[f].resource for f in fields if f in FIELDS and FIELDS[f].resource}
        if len(resources) > 1:
            return False
    xdr = "xdr" in sensors or target not in TARGET_FIELDS
    operation = any(name.endswith("Operation") for name in fields)
    for rule_target, rule_field, scope, require in ALERT_OR_OPERATION:
        if rule_target is not None and rule_target != target:
            continue
        if scope == "xdr" and not xdr:
            continue
        has_operation = rule_field in fields if rule_field else operation
        if alert and has_operation:
            return False
        if require and not (alert or has_operation):
            return False
    return True


def detection_findings(detection: Any) -> tuple[list[Finding], str | None, list[str]]:
    """The findings of a ``detection`` table, its target, and its criteria fields."""
    if not isinstance(detection, Mapping):
        return [], None, []
    found: list[Finding] = []
    target = detection.get("target")
    if not isinstance(target, str) or target not in DETECTION_TARGETS:
        found.append(("bitdefender_target", ("detection", "target")))
        target = None
    criteria = detection.get("criteria")
    if not isinstance(criteria, list) or not criteria:
        found.append(("bitdefender_criterion_shape", _CRITERIA))
        return found, target, []
    shaped: list[Mapping[str, Any]] = []
    for index, criterion in enumerate(criteria):
        path = (*_CRITERIA, str(index))
        if not _criterion_shape_ok(criterion):
            found.append(("bitdefender_criterion_shape", path))
            continue
        shaped.append(criterion)
        if target is not None:
            found.extend((code, path) for code in sorted(_criterion_codes(target, criterion)))
    fields = [str(c["field"]) for c in shaped]
    if (
        target is not None
        and shaped
        and len(shaped) == len(criteria)
        and not any(path[:2] == _CRITERIA and len(path) == 3 for _, path in found)
        and not _combination_ok(target, shaped, detection.get("alert"))
    ):
        found.append(("bitdefender_criteria_combination", _CRITERIA))
    return found, target, fields


def action_scope_findings(
    actions: Any, *, kind: str, target: str | None, fields: list[str]
) -> list[Finding]:
    """``bitdefender_action_scope`` at ``actions.<key>`` for each action the rule cannot take."""
    if not isinstance(actions, Mapping):
        return []
    keys = [key for key in actions if key in ACTION_TYPES]
    if kind == "yara":
        refused = [key for key in keys if key in NOT_ON_YARA]
    elif target in ("process", "file") or any(".CreatedBy." in field for field in fields):
        refused = []
    else:
        refused = [key for key in keys if key in PROCESS_ACTIONS]
    return [("bitdefender_action_scope", ("actions", str(key))) for key in refused]


def targets_codes(targets: Any) -> set[str]:
    """``bitdefender_targets_shape``: at most one list, each non-empty."""
    if not isinstance(targets, Mapping):
        return set()
    present = [key for key in ("endpoint_tags", "companies") if key in targets]
    if len(present) > 1:
        return {"bitdefender_targets_shape"}
    for key in present:
        value = targets[key]
        if not isinstance(value, list) or not value:
            return {"bitdefender_targets_shape"}
    return set()


def strip_yara_comments_and_strings(text: str) -> str:
    """*text* with comments removed and text strings emptied, so keywords inside them vanish."""
    return _YARA_COMMENT_OR_STRING.sub(
        lambda match: '""' if match.group(0).startswith('"') else " ", text
    )


def yara_rules(text: str) -> list[tuple[str, bool]]:
    """``(name, private_or_global)`` for each YARA rule declared in *text*."""
    code = strip_yara_comments_and_strings(text)
    return [(match.group(2), bool(match.group(1).strip())) for match in _YARA_RULE.finditer(code)]


def yara_signature_codes(signature: Any) -> set[str]:
    """The parser-free yara-1.0 codes and the Bitdefender profile codes for *signature*."""
    if not isinstance(signature, str):
        return set()
    codes: set[str] = set()
    if not signature.isascii():
        codes.add("bitdefender_yara_ascii")
    if len(signature) > YARA_MAX_CHARACTERS:
        codes.add("bitdefender_yara_size")
    if _YARA_INCLUDE.search(strip_yara_comments_and_strings(signature)):
        codes.add("yara_include")
    rules = yara_rules(signature)
    if not any(not hidden for _, hidden in rules):
        codes.add("yara_empty_signature")
    names = [name for name, _ in rules]
    if len(names) != len(set(names)):
        codes.add("yara_duplicate_rule")
    return codes


#: Field names of the criterion keys, as a dumped (not by-alias) model spells them.
_FIELD_NAMES = {"is_": "is", "any_": "any"}


def _as_authored(value: Any) -> Any:
    """*value* without ``None`` members, with field names read as their keys.

    A block can come back from ``model_dump()``: every optional key is then
    present as ``None``, and ``is``/``any`` may be spelled ``is_``/``any_``.
    Neither is a key the author wrote.
    """
    if isinstance(value, Mapping):
        return {
            _FIELD_NAMES.get(str(key), key): _as_authored(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_as_authored(item) for item in value]
    return value


def block_findings(block: Mapping[str, Any]) -> list[Finding]:
    """Every bitdefender-1.0 constraint finding of a block, as authored, at its path."""
    raw = _as_authored(block)
    found: list[Finding] = []
    detection = raw.get("detection")
    yara = raw.get("yara")
    if (detection is None) == (yara is None):
        found.append(("bitdefender_rule_kind", ()))
    severity = raw.get("severity")
    if severity is not None and severity not in SEVERITIES:
        found.append(("bitdefender_severity", ("severity",)))
    found.extend((code, ("targets",)) for code in targets_codes(raw.get("targets")))
    target: str | None = None
    fields: list[str] = []
    if detection is not None:
        detection_found, target, fields = detection_findings(detection)
        found.extend(detection_found)
    if isinstance(yara, Mapping):
        signature = yara.get("signature")
        codes = (
            {"yara_empty_signature"}
            if isinstance(signature, str) and not signature.strip()
            else yara_signature_codes(signature)
        )
        found.extend((code, ("yara", "signature")) for code in sorted(codes))
    if (detection is None) != (yara is None):
        kind = "detection" if detection is not None else "yara"
        if kind == "yara" or target is not None:
            found.extend(
                action_scope_findings(raw.get("actions"), kind=kind, target=target, fields=fields)
            )
    return found


def block_codes(block: Mapping[str, Any]) -> set[str]:
    """Every bitdefender-1.0 constraint code a block, as authored, breaks."""
    return {code for code, _ in block_findings(block)}
