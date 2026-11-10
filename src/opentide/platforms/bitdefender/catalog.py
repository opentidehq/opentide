"""The Bitdefender GravityZone criteria catalogue and block checks (bitdefender-1.0).

Static validation of a ``configurations.bitdefender`` block: the constraint
codes of the spec (``bitdefender_*``) and the parser-free YARA checks of
yara-1.0 (``yara_include``, ``yara_empty_signature``, ``yara_duplicate_rule``)
under the Bitdefender profile (``bitdefender_yara_ascii``,
``bitdefender_yara_size``). :func:`block_codes` reads the block as authored, so
:class:`~opentide.models.platform.BitdefenderConfig` can report every code at
once, before the field types run.

The catalogue covers the EDR targets the spec tables list. A field on any other
detection target is not checked here: the spec makes an unknown field there a
warning until the catalogue covers it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

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

#: Fields per EDR target (bitdefender-1.0, Criteria catalogue).
TARGET_FIELDS: dict[str, frozenset[str]] = {
    "process": frozenset(
        {
            "Process.Name",
            "Process.Path",
            "Process.FullPathName",
            "Process.CommandLine",
            "Process.Parent.Name",
            "Process.Parent.Path",
            "Process.Parent.FullPathName",
            "Process.Parent.CommandLine",
            "Process.User",
            "Process.MD5",
            "Process.SHA2",
        }
    ),
    "file": frozenset(
        {
            "File.Name",
            "File.Path",
            "File.FullPathName",
            "File.Operation",
            "File.CreatedBy.Name",
            "File.CreatedBy.Path",
            "File.CreatedBy.FullPathName",
            "File.CreatedBy.CommandLine",
            "File.CreatedBy.User",
            "File.CertificateSigner",
            "File.CertificateIssuer",
            "File.CertificateSignedStatus",
            "File.MD5",
            "File.SHA2",
            "File.Url",
            "File.SourceIP",
            "File.DestinationIP",
        }
    ),
    "connection": frozenset(
        {
            "Connection.SourceIP",
            "Connection.DestinationIP",
            "Connection.SourcePort",
            "Connection.DestinationPort",
            "Connection.Process.Name",
            "Connection.Process.Path",
            "Connection.Process.FullPathName",
            "Connection.Process.CommandLine",
            "Connection.Process.User",
            "Connection.URL",
            "Connection.Domain",
            "Connection.Protocol",
            "Connection.HTTPUser",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.FTPUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.WMIExecQuery",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
        }
    ),
    "registry": frozenset(
        {
            "Registry.Key",
            "Registry.Value",
            "Registry.Data",
            "Registry.DataType",
            "Registry.Operation",
            "Registry.CreatedBy.Name",
            "Registry.CreatedBy.Path",
            "Registry.CreatedBy.FullPathName",
            "Registry.CreatedBy.CommandLine",
        }
    ),
}

#: Enum fields and their values (bitdefender-1.0, Criteria catalogue).
ENUM_VALUES: dict[str, frozenset[str]] = {
    "File.Operation": frozenset(
        {"rename", "copy", "create", "shared", "downloaded", "uploaded", "read", "write", "move"}
    ),
    "File.CertificateSignedStatus": frozenset({"is_signed", "is_unsigned"}),
    "Connection.Protocol": frozenset({"http/https", "smb"}),
    "Connection.FileRemoteOperation": frozenset({"create", "rem_delete", "read", "write", "move"}),
    "Registry.Operation": frozenset(
        {
            "key_created",
            "key_deleted",
            "key_renamed",
            "value_created",
            "value_deleted",
            "value_written",
        }
    ),
    "Registry.DataType": frozenset(
        {
            "string",
            "expandablestring",
            "dword",
            "qword",
            "binary",
            "none",
            "link",
            "resource_list",
            "full_resource_descriptor",
            "resource_requirements_list",
        }
    ),
}

PORT_FIELDS: frozenset[str] = frozenset({"Connection.SourcePort", "Connection.DestinationPort"})

#: XDR-only fields of the ``file`` target.
XDR_FIELDS: frozenset[str] = frozenset(
    {"File.MD5", "File.SHA2", "File.Url", "File.SourceIP", "File.DestinationIP"}
)
#: ``File.Operation`` values for EDR only, and for XDR only.
EDR_OPERATIONS: frozenset[str] = frozenset({"rename", "copy", "create"})
XDR_OPERATIONS: frozenset[str] = frozenset({"shared", "downloaded", "uploaded"})
#: Fields an EDR sensor reports and XDR does not.
EDR_FIELD_PREFIXES: tuple[str, ...] = ("File.CreatedBy.", "File.Certificate")

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
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def _criterion_shape_ok(criterion: Any) -> bool:
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


def _criterion_codes(target: str, criterion: Mapping[str, Any]) -> set[str]:
    codes: set[str] = set()
    field = str(criterion["field"])
    relation = next(key for key in RELATIONS if key in criterion)
    value = criterion[relation]
    values = value if relation == "any" else [value]
    known = TARGET_FIELDS.get(target)
    if known is not None and field not in known:
        codes.add("bitdefender_criterion_field")
    enum = ENUM_VALUES.get(field)
    if enum is not None:
        if relation == "contains":
            codes.add("bitdefender_criterion_relation")
        elif not all(isinstance(item, str) and item in enum for item in values):
            codes.add("bitdefender_criterion_value")
    if relation == "contains" and field.endswith((".MD5", ".SHA2")):
        codes.add("bitdefender_criterion_relation")
    if field in PORT_FIELDS and not all(map(_port, values)):
        codes.add("bitdefender_criterion_value")
    return codes


def _combination_ok(target: str, criteria: list[Mapping[str, Any]], alert: Any) -> bool:
    fields = [str(c["field"]) for c in criteria]
    operations: set[Any] = set()
    for criterion in criteria:
        if criterion["field"] == "File.Operation":
            relation = next(key for key in RELATIONS if key in criterion)
            value = criterion[relation]
            operations.update(value if relation == "any" else [value])
    xdr = any(field in XDR_FIELDS for field in fields) or bool(operations & XDR_OPERATIONS)
    edr = any(field.startswith(EDR_FIELD_PREFIXES) for field in fields) or bool(
        operations & EDR_OPERATIONS
    )
    if xdr and edr:
        return False
    if any(field.startswith("File.Certificate") for field in fields) and not (
        {"File.Name", "File.FullPathName"} & set(fields)
    ):
        return False
    if "Connection.Protocol" in fields and "Connection.Domain" not in fields:
        return False
    xdr_detection = xdr or target not in TARGET_FIELDS
    has_operation = any(field.endswith("Operation") for field in fields)
    return not (xdr_detection and alert and has_operation)


def detection_codes(detection: Any) -> tuple[set[str], str | None, list[str]]:
    """The codes of a ``detection`` table, its target, and its criteria fields."""
    if not isinstance(detection, Mapping):
        return set(), None, []
    codes: set[str] = set()
    target = detection.get("target")
    if not isinstance(target, str) or target not in DETECTION_TARGETS:
        codes.add("bitdefender_target")
        target = None
    criteria = detection.get("criteria")
    if not isinstance(criteria, list):
        return codes, target, []
    shaped = [c for c in criteria if _criterion_shape_ok(c)]
    if len(shaped) != len(criteria):
        codes.add("bitdefender_criterion_shape")
    fields = [str(c["field"]) for c in shaped]
    if target is None:
        return codes, target, fields
    for criterion in shaped:
        codes |= _criterion_codes(target, criterion)
    if shaped and not _combination_ok(target, shaped, detection.get("alert")):
        codes.add("bitdefender_criteria_combination")
    return codes, target, fields


def action_scope_codes(
    actions: Any, *, kind: str, target: str | None, fields: list[str]
) -> set[str]:
    """``bitdefender_action_scope`` when an action is not allowed for the kind and target."""
    if not isinstance(actions, Mapping):
        return set()
    keys = {key for key in actions if key in ACTION_TYPES}
    if kind == "yara":
        return {"bitdefender_action_scope"} if keys & NOT_ON_YARA else set()
    if not keys & PROCESS_ACTIONS:
        return set()
    if target in ("process", "file") or any(".CreatedBy." in field for field in fields):
        return set()
    return {"bitdefender_action_scope"}


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


def block_codes(block: Mapping[str, Any]) -> set[str]:
    """Every bitdefender-1.0 constraint code a block, as authored, breaks."""
    raw = _as_authored(block)
    codes: set[str] = set()
    detection = raw.get("detection")
    yara = raw.get("yara")
    if (detection is None) == (yara is None):
        codes.add("bitdefender_rule_kind")
    severity = raw.get("severity")
    if severity is not None and severity not in SEVERITIES:
        codes.add("bitdefender_severity")
    codes |= targets_codes(raw.get("targets"))
    target: str | None = None
    fields: list[str] = []
    if detection is not None:
        found, target, fields = detection_codes(detection)
        codes |= found
    if yara is not None and isinstance(yara, Mapping):
        signature = yara.get("signature")
        if isinstance(signature, str) and not signature.strip():
            codes.add("yara_empty_signature")
        else:
            codes |= yara_signature_codes(signature)
    if (detection is None) != (yara is None):
        kind = "detection" if detection is not None else "yara"
        if kind == "yara" or target is not None:
            codes |= action_scope_codes(raw.get("actions"), kind=kind, target=target, fields=fields)
    return codes
