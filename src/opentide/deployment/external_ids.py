"""Deploy-time handling of vendor rule ids (RFC 0010 §5).

Defender for Endpoint, SentinelOne and CrowdStrike deployers ask
:func:`plan_external_id` what to do for one rule on one tenant *before* any
HTTP call. The answer comes from the deployment state shard alone: there is
no fallback to ids on the rule, and a rule that still carries
``rule_id``/``rule_id_bundle``/``rule_id::<tenant>`` is refused.

| Legacy key | Shard entry | Result |
|------------|-------------|--------|
| present    | any         | ``external_id_in_rule``, no HTTP |
| absent     | present     | update (disablement included), or delete |
| absent     | absent      | create, unless ``DELETION``/``DISABLEMENT``: ``external_id_missing`` |

A create is also refused, before any HTTP call, while git ignores the shard
directory (``deployment_state_ignored``) and when the run cannot persist the
id it would record (``deployment_state_unpersisted``): in CI under any plan
other than ``PRODUCTION``, because only the generated production job commits
``.opentide/states/deployment/``. ``opentide deploy --persist-state-externally``
lifts that refusal for a pipeline that commits the shards itself.

``external_id_missing`` is a warning, not a failure: nothing is known to exist
on that tenant, so there is nothing to disable or delete, and retiring a rule
that never reached a tenant must not fail the run. Every other code is an
error that fails the run.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from opentide.core.logging import get_logger
from opentide.models.deployment_enums import StatusStrategy
from opentide.states.deployment import (
    DeploymentState,
    DeploymentStateError,
    deployment_state_ignore,
    forget_external_id,
    ignored_message,
    legacy_external_id_keys,
    record_external_id,
)

logger = get_logger(__name__)

#: Set by ``opentide deploy --persist-state-externally`` for the run.
PERSIST_EXTERNALLY_ENV = "OPENTIDE_PERSIST_STATE_EXTERNALLY"

MIGRATE_ADVICE = (
    "Run 'opentide deploy migrate-state' and commit the stripped rules together "
    "with .opentide/states/deployment/"
)


@dataclass(frozen=True)
class ExternalIdAction:
    """What a deployer does for one rule on one tenant."""

    kind: Literal["create", "update", "delete"]
    external_id: str | None = None


def _status_strategy(status: object) -> StatusStrategy:
    if isinstance(status, StatusStrategy):
        return status
    from opentide.deployment.utils import check_status

    return check_status(str(status))


def raw_rule_document(object_uuid: str) -> Mapping[str, Any] | None:
    """The rule as authored (before loading drops unknown keys), from the object index."""
    from opentide.core import registry

    try:
        body = registry.Opentide.Models.rules.get(object_uuid)
    except Exception:
        return None
    return body if isinstance(body, Mapping) else None


def legacy_key_error(
    object_uuid: str, document: Mapping[str, Any] | None
) -> DeploymentStateError | None:
    """``external_id_in_rule`` when the authored rule still has a vendor id on any block."""
    legacy = legacy_external_id_keys(document) if document is not None else []
    if not legacy:
        return None
    keys = ", ".join(f"configurations.{platform}.{key}" for platform, key in legacy)
    return DeploymentStateError(
        "external_id_in_rule",
        f"rule {object_uuid} still carries vendor ids on the rule ({keys}); "
        "deploy reads them only from .opentide/states/deployment/",
        advice=MIGRATE_ADVICE,
    )


def without_legacy_external_ids(rules: list[Any], *, platform: str) -> list[Any]:
    """Drop and report rules that still carry a vendor id, before any client is built.

    HarfangLab, Carbon Black and Elastic never read the id, but a rule with the
    key is invalid on every platform and must be migrated, not deployed around.
    """
    kept: list[Any] = []
    for rule in rules:
        object_uuid = str(rule.metadata.uuid)
        error = legacy_key_error(object_uuid, raw_rule_document(object_uuid))
        if error is None:
            kept.append(rule)
            continue
        report_failure(error, object_uuid=object_uuid, platform=platform)
    return kept


def _plan_name(plan: object) -> str | None:
    """The deployment plan of this run: *plan*, else ``DEPLOYMENT_PLAN``."""
    if plan is not None:
        return getattr(plan, "name", str(plan)).upper()
    from opentide.models.deployment_enums import DeploymentStrategy

    try:
        return DeploymentStrategy.load_from_environment().name
    except ValueError:
        return None


def unpersisted_error(
    *, object_uuid: str, platform: str, tenant_name: str, plan: object = None
) -> DeploymentStateError | None:
    """``deployment_state_unpersisted`` when this run could create an id nobody commits.

    Only the generated production job commits ``.opentide/states/deployment/``.
    A create anywhere else in CI (a pull-request STAGING job, a FULL, ALWAYS or
    MANUAL run) would leave the only copy of the new id on a runner that is
    thrown away, and the next run would create the rule again. A local run may
    create: the operator commits the shard. ``--persist-state-externally``
    says the pipeline commits the shards itself.
    """
    if os.environ.get(PERSIST_EXTERNALLY_ENV):
        return None
    from opentide.deployment.ci import CIEnvironment

    if CIEnvironment().environment is CIEnvironment.CIPlatforms.LocalDebug:
        return None
    name = _plan_name(plan)
    if name == "PRODUCTION":
        return None
    return DeploymentStateError(
        "deployment_state_unpersisted",
        f"rule {object_uuid} has no {platform} id for tenant {tenant_name.strip()!r}, and "
        f"this {name or 'unknown'} run in CI cannot keep the id a create would return: only "
        "the generated production job commits .opentide/states/deployment/. The create "
        "was refused before any vendor call. Deploy the rule from the production job, or "
        "pass --persist-state-externally if this pipeline commits "
        ".opentide/states/deployment/ itself.",
    )


def plan_external_id(
    *,
    object_uuid: str,
    platform: str,
    tenant_name: str,
    status: object,
    raw_rule: Mapping[str, Any] | None = None,
    workspace: Path | None = None,
    plan: object = None,
) -> ExternalIdAction:
    """Decide create, update or delete from the shard, or raise a coded error.

    *plan* is the run's deployment plan; ``None`` reads ``DEPLOYMENT_PLAN``.
    """
    document = raw_rule if raw_rule is not None else raw_rule_document(object_uuid)
    legacy = legacy_key_error(object_uuid, document)
    if legacy is not None:
        raise legacy
    state = DeploymentState.load(object_uuid, workspace)
    external_id = state.get(platform, tenant_name)
    strategy = _status_strategy(status)
    if external_id is not None:
        ignore = deployment_state_ignore(workspace)
        if ignore is not None:
            _warn(
                "deployment_state_ignored",
                ignored_message(ignore),
                object_uuid=object_uuid,
                platform=platform,
                tenant=tenant_name,
            )
        if strategy is StatusStrategy.DELETION:
            return ExternalIdAction("delete", external_id)
        return ExternalIdAction("update", external_id)
    if strategy in (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT):
        raise DeploymentStateError(
            "external_id_missing",
            f"rule {object_uuid} has no {platform} id for tenant {tenant_name.strip()!r} in "
            f"{state.path}, so nothing is known to exist on that tenant and there is "
            f"nothing to {strategy.name.lower()}. If a remote copy exists, it must be "
            "removed by hand.",
        )
    ignore = deployment_state_ignore(workspace)
    if ignore is not None:
        raise DeploymentStateError("deployment_state_ignored", ignored_message(ignore))
    unpersisted = unpersisted_error(
        object_uuid=object_uuid, platform=platform, tenant_name=tenant_name, plan=plan
    )
    if unpersisted is not None:
        raise unpersisted
    return ExternalIdAction("create")


def record_created(
    *,
    object_uuid: str,
    platform: str,
    tenant_name: str,
    external_id: object,
    workspace: Path | None = None,
) -> str:
    """Write the id a create returned. A failure names the id and does not roll back."""
    try:
        stored = record_external_id(object_uuid, platform, tenant_name, external_id, workspace)
    except (OSError, DeploymentStateError) as exc:
        raise DeploymentStateError(
            "deployment_state_write_failed",
            f"{platform} created rule {external_id!r} for {object_uuid} on tenant "
            f"{tenant_name.strip()!r}, but the deployment state could not be written "
            f"({exc}). The remote rule was not removed; add the id to "
            ".opentide/states/deployment/ by hand before the next deploy.",
            external_id=str(external_id),
        ) from exc
    # WARNING, not INFO: the default console level is WARNING, and a CI log
    # that loses its runner must still show every id this run created.
    logger.warning(
        "external_id_recorded",
        uuid=object_uuid,
        platform=platform,
        tenant=tenant_name.strip(),
        external_id=stored,
    )
    return stored


def record_deleted(
    *,
    object_uuid: str,
    platform: str,
    tenant_name: str,
    workspace: Path | None = None,
) -> None:
    """Drop the tenant entry after the vendor confirmed the delete."""
    try:
        forget_external_id(object_uuid, platform, tenant_name, workspace)
    except (OSError, DeploymentStateError) as exc:
        raise DeploymentStateError(
            "deployment_state_write_failed",
            f"{platform} deleted the rule for {object_uuid} on tenant {tenant_name.strip()!r}, "
            f"but the deployment state could not be updated ({exc})",
        ) from exc
    logger.info(
        "external_id_removed", uuid=object_uuid, platform=platform, tenant=tenant_name.strip()
    )


#: Codes that skip the rule on that tenant without failing the run.
WARNING_CODES: frozenset[str] = frozenset({"external_id_missing"})


def report_failure(
    error: DeploymentStateError, *, object_uuid: str, platform: str, tenant_name: str = ""
) -> None:
    """Log a coded per-rule refusal. Other rules continue.

    An error marks the run as failed. A code in :data:`WARNING_CODES` marks
    it as warned instead.
    """
    fields: dict[str, Any] = {
        "uuid": object_uuid,
        "platform": platform,
        "tenant": tenant_name.strip(),
    }
    fields.update({key: value for key, value in error.context.items() if key not in fields})
    if error.code in WARNING_CODES:
        _warn(error.code, error.message, **fields)
        return
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    logger.error(error.code, detail=error.message, code=error.code, **fields)


def _warn(code: str, message: str, **fields: Any) -> None:
    os.environ["DEPLOYMENT_WARNING_RAISED"] = "1"
    logger.warning(code, detail=message, code=code, **fields)


def screen_tenant(
    rules: list[Any],
    *,
    platform: str,
    tenant_name: str,
    status_of: Any,
    workspace: Path | None = None,
    plan: object = None,
) -> list[tuple[Any, ExternalIdAction]]:
    """Plan every rule for one tenant before the client is built; drop and report failures."""
    planned: list[tuple[Any, ExternalIdAction]] = []
    for rule in rules:
        object_uuid = str(rule.metadata.uuid)
        try:
            action = plan_external_id(
                object_uuid=object_uuid,
                platform=platform,
                tenant_name=tenant_name,
                status=status_of(rule),
                workspace=workspace,
                plan=plan,
            )
        except DeploymentStateError as error:
            report_failure(
                error, object_uuid=object_uuid, platform=platform, tenant_name=tenant_name
            )
            continue
        planned.append((rule, action))
    return planned
