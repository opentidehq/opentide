"""What a deploy would do to each rule on each tenant, before anything is sent.

Every planned change is one rule on one tenant (or on a platform with no
tenant yet), with one action:

``create`` / ``update``
    Platforms that keep vendor ids in ``.opentide/states/deployment/``
    (CrowdStrike, Defender for Endpoint, SentinelOne): ``update`` when the
    shard holds an id for the tenant, otherwise ``create``.
``upsert``
    Platforms that address a rule by its own UUID (Sentinel, Splunk, Elastic,
    Carbon Black, HarfangLab) write it whether or not it exists; opentide
    cannot tell a create from an update without asking the vendor, so it does
    not claim either.
``disable`` / ``delete``
    The rule's status maps to ``DISABLEMENT`` or ``DELETION``.

The same plan counts a real run's outcome: ``Deployed 3 rules to 2 tenants
· 1 created, 2 updated``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from opentide.cli.ui.progress import plural

Action = Literal["create", "update", "upsert", "disable", "delete"]

#: Tally order, and the words each action takes in a plan and in an outcome.
ACTIONS: tuple[Action, ...] = ("create", "update", "upsert", "disable", "delete")
_PLANNED = {
    "create": "to create",
    "update": "to update",
    "upsert": "to create or update",
    "disable": "to disable",
    "delete": "to delete",
}
_DONE = {
    "create": "created",
    "update": "updated",
    "upsert": "created or updated",
    "disable": "disabled",
    "delete": "deleted",
}


@dataclass(frozen=True)
class PlannedChange:
    """One rule on one tenant (``None`` when the platform has no tenant yet)."""

    platform: str
    tenant: str | None
    uuid: str
    name: str
    status: str
    action: Action

    def to_dict(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "tenant": self.tenant,
            "uuid": self.uuid,
            "name": self.name,
            "status": self.status,
            "action": self.action,
        }


def _rule_status(rule: Any, platform: str) -> str:
    config = getattr(getattr(rule, "configurations", None), platform, None)
    return str(getattr(config, "status", "") or "")


def _action(platform: str, tenant: str | None, uuid: str, status: str) -> Action:
    from opentide.models.deployment_enums import StatusStrategy
    from opentide.states.deployment import STATE_PLATFORMS, DeploymentState

    try:
        from opentide.deployment.utils import check_status

        strategy = check_status(status)
    except Exception:  # noqa: BLE001 -- an unknown status fails the deploy, not the plan
        strategy = None
    if strategy is StatusStrategy.DELETION:
        return "delete"
    if strategy is StatusStrategy.DISABLEMENT:
        return "disable"
    if platform not in STATE_PLATFORMS:
        return "upsert"
    if tenant is None:
        return "create"
    try:
        known = DeploymentState.load(uuid).get(platform, tenant)
    except Exception:  # noqa: BLE001 -- the deployer reports a bad shard
        known = None
    return "update" if known else "create"


def plan_changes(
    deployment_list: Mapping[str, Sequence[str]],
    targets: Mapping[str, Mapping[str, Sequence[str]]],
) -> list[PlannedChange]:
    """Every rule on every tenant *targets* resolved; rules on tenantless platforms once."""
    from opentide.core.registry import Opentide

    changes: list[PlannedChange] = []
    for platform, uuids in deployment_list.items():
        tenants = targets.get(platform) or {}
        pairs = (
            [(tenant, uuid) for tenant, ids in tenants.items() for uuid in ids]
            if tenants
            else [(None, uuid) for uuid in uuids]
        )
        for tenant, uuid in pairs:
            try:
                rule = Opentide.Rules[uuid]
            except Exception:  # noqa: BLE001 -- planning already refused a missing rule
                rule = None
            name = str(getattr(rule, "name", "") or uuid)
            status = _rule_status(rule, platform)
            changes.append(
                PlannedChange(
                    platform=platform,
                    tenant=tenant,
                    uuid=str(uuid),
                    name=name,
                    status=status,
                    action=_action(platform, tenant, str(uuid), status),
                )
            )
    return changes


def tally(changes: Sequence[PlannedChange]) -> dict[str, int]:
    """Changes per action, every action present."""
    counts = Counter(change.action for change in changes)
    return {action: counts.get(action, 0) for action in ACTIONS}


def plan_summary(
    changes: Sequence[PlannedChange], platforms: Sequence[str], tenants: int
) -> dict[str, int]:
    """The JSON ``summary`` of a plan: one count per action, platforms and tenants."""
    return {**tally(changes), "platforms": len(platforms), "tenants": tenants}


def plan_message(changes: Sequence[PlannedChange], platforms: Sequence[str], tenants: int) -> str:
    """``Plan: 1 to create, 0 to update, 0 to disable, 0 to delete · 1 platform, 0 tenants``."""
    counts = tally(changes)
    parts = [
        f"{counts[action]} {_PLANNED[action]}"
        for action in ACTIONS
        if action != "upsert" or counts[action]
    ]
    scope = f"{plural(len(platforms), 'platform')}, {plural(tenants, 'tenant')}"
    return f"Plan: {', '.join(parts)} · {scope}"


def deployed_message(changes: Sequence[PlannedChange], seconds: float) -> str:
    """``Deployed 3 rules to 2 tenants · 1 created, 2 updated · 12.4s``."""
    from opentide.cli.ui.progress import seconds_text

    rules = len({change.uuid for change in changes})
    tenants = len({(change.platform, change.tenant) for change in changes if change.tenant})
    counts = tally(changes)
    done = ", ".join(f"{counts[action]} {_DONE[action]}" for action in ACTIONS if counts[action])
    parts = [f"Deployed {plural(rules, 'rule')} to {plural(tenants, 'tenant')}"]
    if done:
        parts.append(done)
    parts.append(seconds_text(seconds))
    return " · ".join(parts)
