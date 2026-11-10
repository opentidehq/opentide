"""Compile an opentide rule's Bitdefender block into GravityZone JSON-RPC params (bitdefender-1.0).

The author writes the kind (``detection`` criteria or a YARA ``signature``),
actions and targets; this module derives the rest from the opentide rule: the
GravityZone name, description, severity and tags. :func:`create_params`,
:func:`update_params` and :func:`delete_params` build the ``params`` of
``createCustomRule``, ``updateCustomRule`` and ``deleteCustomRule``; every
update carries the whole payload, because GravityZone keeps the stored value
of any optional parameter it is not sent.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from opentide.models.deployment_enums import StatusStrategy
from opentide.models.platform import BitdefenderConfig
from opentide.models.platform_configs import (
    BitdefenderActions,
    BitdefenderCriterion,
    BitdefenderProcessScope,
)
from opentide.models.rule import DetectionRule
from opentide.platforms.bitdefender.catalog import ACTION_TYPES, NOT_ON_YARA, SEVERITIES

#: Every call carries ``type: 1``: a detection rule. Exclusion rules (``type: 2``) are never sent.
RULE_TYPE = 1
SUBTYPES: dict[str, int] = {"detection": 0, "yara": 1}

#: ``response.alert_severity`` → ``settings.severity`` (bitdefender-1.0, Severity).
ALERT_SEVERITY: dict[str, int] = {
    "critical": 3,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 1,
}
DEFAULT_SEVERITY = 2

NAME_LIMIT = 128
DESCRIPTION_LIMIT = 1024
TAG_LIMIT = 128
TAG_MINIMUM = 2

#: What GravityZone refuses in names, descriptions and tags, and what deploy sends instead.
LEFT_ANGLE = "\N{SINGLE LEFT-POINTING ANGLE QUOTATION MARK}"
RIGHT_ANGLE = "\N{SINGLE RIGHT-POINTING ANGLE QUOTATION MARK}"
APOSTROPHE = "\N{RIGHT SINGLE QUOTATION MARK}"
QUOTE = "\N{RIGHT DOUBLE QUOTATION MARK}"
ELLIPSIS = "\N{HORIZONTAL ELLIPSIS}"
_REPLACEMENTS = (("<", LEFT_ANGLE), (">", RIGHT_ANGLE), ("'", APOSTROPHE), ('"', QUOTE))


class BitdefenderTargetError(ValueError):
    """``bitdefender_target_unknown``: a ``targets`` alias the tenant does not define."""

    code = "bitdefender_target_unknown"


@dataclass(frozen=True)
class GravityZoneRule:
    """What a block deploys on one tenant, after derivation."""

    uuid: str
    kind: str
    name: str
    description: str
    tags: list[str]
    settings: dict[str, Any]
    targets: dict[str, Any] | None = None
    company_id: str | None = None

    @property
    def subtype(self) -> int:
        return SUBTYPES[self.kind]


def block_of(rule: DetectionRule) -> BitdefenderConfig:
    """The rule's Bitdefender block, or an error naming the rule."""
    configurations = rule.platform_configs()
    block = configurations.bitdefender
    if block is None:
        raise ValueError(f"Rule {rule.metadata.uuid} ({rule.name}) has no bitdefender block")
    return block


def normalise(text: str) -> str:
    """GravityZone refuses ``< > ' "`` and leading whitespace: replace and strip them."""
    for before, after in _REPLACEMENTS:
        text = text.replace(before, after)
    return text.lstrip()


def gravityzone_name(rule_name: str, block_name: str | None) -> str:
    """The shared ``name``, else the rule ``name``, normalised, cut at 128 characters."""
    return normalise(block_name or rule_name)[:NAME_LIMIT]


def derive_description(description: str | None) -> str:
    """Whitespace collapsed, normalised, cut at 1024 characters with a trailing ``…``."""
    text = normalise(" ".join(str(description or "").split()))
    if len(text) <= DESCRIPTION_LIMIT:
        return text
    return text[: DESCRIPTION_LIMIT - 1] + ELLIPSIS


def derive_severity(rule: DetectionRule, block: BitdefenderConfig) -> int:
    """The block ``severity``, else ``response.alert_severity``'s, else Medium (2)."""
    if block.severity:
        return SEVERITIES[block.severity]
    response = rule.response
    if response is None or "alert_severity" not in response.model_fields_set:
        return DEFAULT_SEVERITY
    return ALERT_SEVERITY.get(str(response.alert_severity).strip().lower(), DEFAULT_SEVERITY)


def derive_tags(
    rule: DetectionRule, block: BitdefenderConfig, tenant_tags: Sequence[str] | None = None
) -> list[str]:
    """Block, ATT&CK, ``opentide``, ``opentide:<uuid>`` and tenant tags; normalised, unique."""
    from opentide.platforms.sysdig.compile import rule_techniques

    candidates = [
        *(block.tags or []),
        *rule_techniques(rule),
        "opentide",
        f"opentide:{rule.metadata.uuid}",
        *(tenant_tags or []),
    ]
    tags: list[str] = []
    for candidate in candidates:
        tag = normalise(str(candidate))[:TAG_LIMIT]
        if len(tag) >= TAG_MINIMUM and tag not in tags:
            tags.append(tag)
    return tags


def _scope(value: object) -> dict[str, bool]:
    """``{includeParent, includeChildren}`` of a ``true`` or a scoped action."""
    scope = value if isinstance(value, BitdefenderProcessScope) else BitdefenderProcessScope()
    return {"includeParent": scope.include_parent, "includeChildren": scope.include_children}


def automatic_actions(kind: str, actions: BitdefenderActions | None) -> list[dict[str, Any]]:
    """Every action type the kind allows, in type order, each enabled ``true`` or ``false``."""
    entries: list[dict[str, Any]] = []
    for key, code in ACTION_TYPES.items():
        if kind == "yara" and key in NOT_ON_YARA:
            continue
        value = getattr(actions, key, None) if actions is not None else None
        entry: dict[str, Any] = {"type": code, "enabled": value is not None}
        if value is not None and key in ("kill_process", "quarantine"):
            entry["settings"] = _scope(value)
        elif value is not None and key == "antimalware_scan":
            entry["settings"] = {"type": 1 if value == "quick" else 2}
        entries.append(entry)
    return entries


def _criterion(criterion: BitdefenderCriterion) -> dict[str, Any]:
    for relation, value in (
        ("is", criterion.is_),
        ("contains", criterion.contains),
        ("any", criterion.any_),
    ):
        if value is not None:
            return {"field": criterion.field, "relation": relation, "value": value}
    raise ValueError(f"criterion on {criterion.field} has no relation")


def yara_query(signature: str) -> str:
    """The signature with ``\\n`` line endings and one trailing newline."""
    text = signature.replace("\r\n", "\n").replace("\r", "\n")
    return text if text.endswith("\n") else text + "\n"


def derive_settings(
    rule: DetectionRule,
    block: BitdefenderConfig,
    strategy: StatusStrategy,
    *,
    automatic: bool = True,
) -> dict[str, Any]:
    """``settings`` by kind (bitdefender-1.0, Deploy)."""
    disabled = strategy is StatusStrategy.DISABLEMENT
    severity = derive_severity(rule, block)
    settings: dict[str, Any]
    if block.yara is not None:
        settings = {
            "status": 0 if disabled or not block.yara.on_access else 1,
            "severity": severity,
            "yaraQuery": yara_query(block.yara.signature),
        }
    else:
        detection = block.detection
        if detection is None:
            raise ValueError(f"Rule {rule.metadata.uuid} has neither detection nor yara")
        settings = {
            "status": 0 if disabled else 1,
            "severity": severity,
            "target": detection.target,
            "criteriaList": [_criterion(c) for c in detection.criteria],
        }
        if detection.alert:
            settings["filters"] = [{"field": "detection", "value": detection.alert}]
    if automatic:
        settings["automaticActions"] = automatic_actions(block.kind, block.actions)
    return settings


def resolve_targets(
    targets: Mapping[str, Any] | None,
    endpoint_tags: Mapping[str, Mapping[str, str]] | None,
    companies: Mapping[str, str] | None,
) -> dict[str, Any] | None:
    """``targets`` aliases to GravityZone ids; ``bitdefender_target_unknown`` for an unknown one."""
    if not targets:
        return None
    if targets.get("endpoint_tags"):
        known = endpoint_tags or {}
        missing = [alias for alias in targets["endpoint_tags"] if alias not in known]
        if missing:
            raise BitdefenderTargetError(
                f"bitdefender_target_unknown: endpoint tag alias(es) {', '.join(missing)} "
                "are not in the tenant's endpoint_tags table"
            )
        return {
            "endpointTags": [
                {"tagId": known[alias]["tag_id"], "companyId": known[alias]["company_id"]}
                for alias in targets["endpoint_tags"]
            ]
        }
    if targets.get("companies"):
        known_companies = companies or {}
        missing = [alias for alias in targets["companies"] if alias not in known_companies]
        if missing:
            raise BitdefenderTargetError(
                f"bitdefender_target_unknown: company alias(es) {', '.join(missing)} "
                "are not in the tenant's companies table"
            )
        return {"companiesIds": [known_companies[alias] for alias in targets["companies"]]}
    return None


def compile_rule(
    rule: DetectionRule,
    strategy: StatusStrategy,
    setup: Any | None = None,
) -> GravityZoneRule:
    """What *rule* deploys under *strategy* on the tenant whose ``setup`` is given.

    Without a tenant (an offline preview) there are no tenant tags or default
    targets, block target aliases stay unresolved, and actions are sent.
    """
    block = block_of(rule)
    automatic = bool(getattr(setup, "automatic_actions", True)) if setup is not None else True
    targets: dict[str, Any] | None = None
    block_targets = (
        block.targets.model_dump(exclude_none=True) if block.targets is not None else None
    )
    if setup is not None:
        targets = resolve_targets(
            block_targets or getattr(setup, "targets", None),
            getattr(setup, "endpoint_tags", None),
            getattr(setup, "companies", None),
        )
    elif block_targets:
        targets = {
            "endpointTags" if "endpoint_tags" in block_targets else "companiesIds": next(
                iter(block_targets.values())
            )
        }
    return GravityZoneRule(
        uuid=str(rule.metadata.uuid),
        kind=block.kind,
        name=gravityzone_name(rule.name, block.name),
        description=derive_description(rule.description),
        tags=derive_tags(rule, block, getattr(setup, "tags", None) if setup is not None else None),
        settings=derive_settings(rule, block, strategy, automatic=automatic),
        targets=targets,
        company_id=getattr(setup, "company_id", None) if setup is not None else None,
    )


def create_params(compiled: GravityZoneRule) -> dict[str, Any]:
    """``createCustomRule`` params, with ``returnRuleId: true``."""
    params: dict[str, Any] = {
        "type": RULE_TYPE,
        "subtype": compiled.subtype,
        "name": compiled.name,
        "description": compiled.description,
        "tags": list(compiled.tags),
        "settings": compiled.settings,
    }
    if compiled.targets:
        params["targets"] = compiled.targets
    if compiled.company_id:
        params["companyId"] = compiled.company_id
    params["returnRuleId"] = True
    return params


def update_params(compiled: GravityZoneRule, rule_id: str) -> dict[str, Any]:
    """``updateCustomRule`` params: ``ruleId`` and the whole payload."""
    params: dict[str, Any] = {
        "ruleId": rule_id,
        "type": RULE_TYPE,
        "name": compiled.name,
        "description": compiled.description,
        "tags": list(compiled.tags),
        "settings": compiled.settings,
    }
    if compiled.targets:
        params["targets"] = compiled.targets
    return params


def delete_params(rule_id: str) -> dict[str, Any]:
    """``deleteCustomRule`` params."""
    return {"ruleId": rule_id, "type": RULE_TYPE}


def request_body(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """The JSON-RPC 2.0 body without its per-request ``id``, as the goldens hold it."""
    return {"jsonrpc": "2.0", "method": method, "params": params}
