"""Compile an opentide rule's Sysdig block into a Falco rule (sysdig-1.0).

The author writes the condition, its exceptions, and the macros and lists only
this rule uses; this module derives the rest from the opentide rule: the rule
name, ``desc``, ``priority``, ``tags`` and a default ``output``.
:func:`api_body` turns the result into the Sysdig Secure ``/api/secure/rules``
payload.
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from opentide._models.deployment_enums import StatusStrategy
from opentide._models.platform import SysdigConfig
from opentide._models.rule import DetectionRule
from opentide.platforms.sysdig.expansion import Expander, join_lines

#: ``response.alert_severity`` → Falco priority (sysdig-1.0, Priority).
SEVERITY_PRIORITY: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "ERROR",
    "medium": "WARNING",
    "low": "NOTICE",
    "informational": "INFORMATIONAL",
}

#: The priority of a rule with no ``response``.
DEFAULT_PRIORITY = "WARNING"

#: Falco priority → the Sysdig API's ``priority`` value.
API_PRIORITY: dict[str, str] = {
    "EMERGENCY": "emergency",
    "ALERT": "alert",
    "CRITICAL": "critical",
    "ERROR": "error",
    "WARNING": "warning",
    "NOTICE": "notice",
    "INFORMATIONAL": "info",
    "DEBUG": "debug",
}

DEFAULT_SOURCE = "syscall"

#: Fields written after the rule name when ``output`` is omitted (sysdig-1.0, Output).
DEFAULT_OUTPUT_FIELDS: dict[str, str] = {
    "syscall": (
        " | evt_type=%evt.type user=%user.name user_uid=%user.uid process=%proc.name"
        " proc_exepath=%proc.exepath parent=%proc.pname command=%proc.cmdline"
        " terminal=%proc.tty container_id=%container.id container_name=%container.name"
        " image=%container.image.repository"
    ),
    "k8s_audit": (
        " | user=%ka.user.name verb=%ka.verb uri=%ka.uri resource=%ka.target.resource"
        " namespace=%ka.target.namespace name=%ka.target.name response=%ka.response.code"
    ),
    "aws_cloudtrail": (
        " | user=%ct.user region=%ct.region event=%ct.name source_ip=%ct.srcip"
        " account=%ct.user.accountid"
    ),
}

#: Status strategy → the Falco maturity tag (sysdig-1.0, Tags).
MATURITY_TAG: dict[StatusStrategy, str] = {
    StatusStrategy.RELEASE: "maturity_stable",
    StatusStrategy.UNIVERSAL: "maturity_stable",
    StatusStrategy.PREVIEW: "maturity_incubating",
}
SANDBOX_TAG = "maturity_sandbox"


@dataclass(frozen=True)
class FalcoRule:
    """The Falco rule a block deploys, after derivation and expansion."""

    uuid: str
    name: str
    tuning: bool
    condition: str | None
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    desc: str = ""
    output: str = ""
    priority: str = DEFAULT_PRIORITY
    source: str = DEFAULT_SOURCE
    tags: list[str] = field(default_factory=list)
    minimum_engine_version: int | None = None


def block_of(rule: DetectionRule) -> SysdigConfig:
    """The rule's Sysdig block, or an error naming the rule."""
    block = rule.platform_configs().sysdig
    if block is None:
        raise ValueError(f"Rule {rule.metadata.uuid} ({rule.name}) has no sysdig block")
    return block


def derive_priority(rule: DetectionRule, block: SysdigConfig) -> str:
    """The block's priority, else ``response.alert_severity``'s, else ``WARNING``."""
    if block.priority:
        value = block.priority.strip().upper()
        return "INFORMATIONAL" if value == "INFO" else value
    if rule.response is None:
        return DEFAULT_PRIORITY
    return SEVERITY_PRIORITY.get(str(rule.alert_severity).strip().lower(), DEFAULT_PRIORITY)


def derive_output(name: str, block: SysdigConfig) -> str:
    """The authored output on one line, else the rule name and the source's fields."""
    if block.output:
        return join_lines(block.output)
    return name + DEFAULT_OUTPUT_FIELDS.get(block.source or DEFAULT_SOURCE, "")


def _rule_techniques(rule: DetectionRule) -> list[str]:
    """The rule's techniques plus the ones inherited through ``detection_model``."""
    from opentide.generation.framework import get_type, techniques_resolver

    techniques = list(rule.techniques or [])
    uuid = rule.metadata.uuid if rule.metadata else ""
    if rule.detection_model and uuid and get_type(uuid, mute=True) is not None:
        # An unresolved detection model adds nothing, as on Elastic.
        with contextlib.suppress(Exception):
            techniques.extend(techniques_resolver(uuid) or [])
    return list(dict.fromkeys(techniques))


def attack_tags(techniques: Sequence[str]) -> list[str]:
    """Technique ids, then a ``mitre_<tactic>`` tag per tactic (Falco's convention)."""
    from opentide.platforms.elastic.attack import (
        NON_ENTERPRISE_PREFIXES,
        TACTIC_MAP,
        TACTIC_ORDER,
        _cached_get_vocab_entry,
    )

    tactics: set[str] = set()
    for technique in techniques:
        entry = _cached_get_vocab_entry("att&ck", technique)
        if not entry or str(entry.get("name", "")).startswith(NON_ENTERPRISE_PREFIXES):
            continue
        stages = _cached_get_vocab_entry("att&ck", technique, "tide.vocab.stages") or []
        if isinstance(stages, str):
            stages = [stages]
        for stage in stages:
            mapped = TACTIC_MAP.get(str(stage).strip().lower())
            if mapped is not None:
                tactics.add(mapped[0])
    tactic_tags = [
        "mitre_" + stage.lower().replace(" ", "_").replace("-", "_")
        for stage, _ in TACTIC_ORDER
        if stage in tactics
    ]
    return [*techniques, *tactic_tags]


def derive_tags(
    rule: DetectionRule,
    block: SysdigConfig,
    strategy: StatusStrategy,
    tenant_tags: Sequence[str] | None = None,
) -> list[str]:
    """Block tags, ATT&CK tags, the maturity tag, tenant tags; de-duplicated, in that order."""
    tags = [
        *(block.tags or []),
        *attack_tags(_rule_techniques(rule)),
        MATURITY_TAG.get(strategy, SANDBOX_TAG),
        *(tenant_tags or []),
    ]
    return list(dict.fromkeys(tags))


def compile_rule(
    rule: DetectionRule,
    strategy: StatusStrategy,
    tenant_tags: Sequence[str] | None = None,
) -> FalcoRule:
    """The Falco rule *rule*'s Sysdig block deploys under *strategy*."""
    block = block_of(rule)
    expander = Expander(
        {macro.name: macro.condition for macro in block.macros or []},
        {item.name: list(item.items) for item in block.lists or []},
    )
    condition = expander.expand(block.condition) if block.condition else None
    exceptions = [
        expander.exception(entry.model_dump(exclude_none=True)) for entry in block.exceptions or []
    ]
    uuid = str(rule.metadata.uuid)
    if block.append_to_rule:
        return FalcoRule(
            uuid=uuid,
            name=block.append_to_rule,
            tuning=True,
            condition=condition,
            exceptions=exceptions,
            minimum_engine_version=block.minimum_engine_version,
        )
    name = block.name or rule.name
    return FalcoRule(
        uuid=uuid,
        name=name,
        tuning=False,
        condition=condition,
        exceptions=exceptions,
        desc=" ".join(rule.description.split()),
        output=derive_output(name, block),
        priority=derive_priority(rule, block),
        source=block.source or DEFAULT_SOURCE,
        tags=derive_tags(rule, block, strategy, tenant_tags),
        minimum_engine_version=block.minimum_engine_version,
    )


def api_body(compiled: FalcoRule) -> dict[str, Any]:
    """The ``/api/secure/rules`` payload (sysdig-1.0, Deploy: api)."""
    details: dict[str, Any] = {"ruleType": "FALCO", "append": compiled.tuning}
    if compiled.tuning:
        if compiled.condition is not None:
            details["condition"] = {"condition": compiled.condition, "components": []}
        if compiled.exceptions:
            details["exceptions"] = compiled.exceptions
        if compiled.minimum_engine_version is not None:
            details["minimumEngineVersion"] = compiled.minimum_engine_version
        return {"name": compiled.name, "description": "", "tags": [], "details": details}
    details["source"] = compiled.source
    details["condition"] = {"condition": compiled.condition or "", "components": []}
    details["output"] = compiled.output
    details["priority"] = API_PRIORITY[compiled.priority]
    if compiled.exceptions:
        details["exceptions"] = compiled.exceptions
    if compiled.minimum_engine_version is not None:
        details["minimumEngineVersion"] = compiled.minimum_engine_version
    return {
        "name": compiled.name,
        "description": compiled.desc,
        "tags": compiled.tags,
        "details": details,
    }
