"""Deploy custom detection rules to Bitdefender GravityZone (bitdefender-1.0).

GravityZone assigns every rule a 24-hex id at create time. It is kept in
``.opentide/states/deployment/`` (deployment-state, RFC 0010), and every
create, update, disable and delete is planned from that shard before any
request: deploy never lists rules (``getCustomRulesList``) nor finds one by
name or tag. Every update sends the whole payload. Exclusion rules
(``type: 2``) are never created, updated or deleted.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from typing import Any

import requests
import structlog

from opentide.core import deploy_events
from opentide.core.registry import Opentide
from opentide.deployment import TideDeployment, check_status
from opentide.deployment.external_ids import (
    ExternalIdAction,
    record_created,
    record_deleted,
    report_failure,
    screen_tenant,
    unpersisted_error,
    without_legacy_external_ids,
)
from opentide.models.deployment_enums import DetectionPlatforms, RunStrategies, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, batch_tenant
from opentide.platforms.bitdefender.client import (
    NOT_FOUND,
    BitdefenderApiError,
    BitdefenderClient,
    BitdefenderTenantError,
)
from opentide.platforms.bitdefender.compile import (
    BitdefenderTargetError,
    GravityZoneRule,
    block_of,
    compile_rule,
    create_params,
    delete_params,
    update_params,
)
from opentide.platforms.plugins import RuleDeployer
from opentide.platforms.transport import tenant_tls_verify
from opentide.states.deployment import (
    DeploymentStateError,
    deployment_state_ignore,
    ignored_message,
)

logger = structlog.get_logger(__name__)
PLATFORM = "bitdefender"

BitdefenderTenant = ConfigurationModels.Systems.Bitdefender.Tenant

_RULE_ID = re.compile(r"[0-9a-f]{24}")


def _deployment_error(code: str, **kwargs: Any) -> None:
    logger.error(code, code=code, **kwargs)
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    deploy_events.note_failure(f"{code}: {kwargs.get('error') or code.replace('_', ' ')}")


def _deployment_warning(code: str, **kwargs: Any) -> None:
    logger.warning(code, code=code, **kwargs)
    os.environ["DEPLOYMENT_WARNING_RAISED"] = "1"


def _strategy(rule: DetectionRule) -> StatusStrategy:
    return check_status(block_of(rule).status)


def returned_rule_id(result: Any) -> str | None:
    """The 24-hex id a ``createCustomRule`` with ``returnRuleId: true`` answered, or ``None``."""
    if isinstance(result, dict):
        result = result.get("ruleId", result.get("id"))
    if isinstance(result, str) and _RULE_ID.fullmatch(result.strip().lower()):
        return result.strip().lower()
    return None


class BitdefenderDeploy(RuleDeployer):
    """Deploy rules to every GravityZone tenant a run reaches."""

    def compile_deployment(
        self,
        data: DetectionRule,
        tenant_config: BitdefenderTenant | None = None,
        strategy: StatusStrategy | None = None,
    ) -> GravityZoneRule:
        """What *data* deploys on *tenant_config* (no tenant: an offline preview)."""
        setup = tenant_config.setup if tenant_config is not None else None
        return compile_rule(data, strategy or _strategy(data), setup)

    def deploy_rule(
        self,
        rule: DetectionRule,
        client: BitdefenderClient,
        tenant: BitdefenderTenant,
        action: ExternalIdAction,
        strategies: RunStrategies | None = None,
    ) -> None:
        """Create, update, disable or delete one rule on one tenant.

        A rule-level failure is recorded and returns; a refused key raises
        :class:`BitdefenderTenantError`, which stops the tenant.
        """
        object_uuid = str(rule.metadata.uuid)
        strategy = _strategy(rule)
        fields = {"uuid": object_uuid, "tenant": tenant.name, "name": rule.name}
        if action.kind == "delete":
            self._delete(object_uuid, client, tenant, action.known_id())
            return
        try:
            compiled = self.compile_deployment(rule, tenant, strategy)
        except BitdefenderTargetError as exc:
            _deployment_error(exc.code, error=str(exc), **fields)
            return
        if not tenant.setup.automatic_actions and block_of(rule).actions is not None:
            _deployment_warning(
                "bitdefender_actions_unsupported",
                detail="the tenant has no automatic actions; the block's actions are not sent",
                **fields,
            )
        if action.kind == "create":
            self._create(rule, client, tenant, compiled)
            return
        rule_id = action.known_id()
        try:
            client.update_rule(update_params(compiled, rule_id))
        except BitdefenderApiError as exc:
            if exc.code == NOT_FOUND:
                self._recreate(rule, client, tenant, compiled, strategy, strategies)
            elif exc.type_mismatch:
                _deployment_error(
                    "bitdefender_kind_changed",
                    error=(
                        f"GravityZone rule {rule_id} is of another kind; changing the kind "
                        "means DELETION, then a new deploy"
                    ),
                    detail=str(exc),
                    **fields,
                )
            else:
                _deployment_error("bitdefender_request_failed", error=str(exc), **fields)
            return
        logger.info("bitdefender_rule_updated", uuid=object_uuid, rule_id=rule_id)

    def _delete(
        self, object_uuid: str, client: BitdefenderClient, tenant: BitdefenderTenant, rule_id: str
    ) -> None:
        try:
            client.delete_rule(delete_params(rule_id))
        except BitdefenderApiError as exc:
            if exc.code != NOT_FOUND:
                _deployment_error(
                    "bitdefender_request_failed",
                    uuid=object_uuid,
                    tenant=tenant.name,
                    error=str(exc),
                )
                return
        logger.info("bitdefender_rule_deleted", uuid=object_uuid, rule_id=rule_id)
        self._forget(object_uuid, tenant)

    def _create(
        self,
        rule: DetectionRule,
        client: BitdefenderClient,
        tenant: BitdefenderTenant,
        compiled: GravityZoneRule,
    ) -> None:
        object_uuid = str(rule.metadata.uuid)
        fields = {"uuid": object_uuid, "tenant": tenant.name, "name": compiled.name}
        params = create_params(compiled)
        try:
            try:
                result = client.create_rule(params)
            except (requests.Timeout, requests.ConnectionError) as first:
                # The create may or may not have happened: send it once more.
                logger.warning("bitdefender_create_retried", error=str(first), **fields)
                try:
                    result = client.create_rule(params)
                except BitdefenderApiError as exc:
                    if exc.name_conflict:
                        _deployment_error(
                            "bitdefender_create_unconfirmed",
                            error=(
                                f"the first create of {compiled.name!r} got no answer and the "
                                "retry found the name taken: the first create may have "
                                "succeeded with an id opentide does not know. Resolve it in the "
                                "GravityZone console (delete the rule, or record its id in "
                                ".opentide/states/deployment/)"
                            ),
                            detail=str(exc),
                            **fields,
                        )
                        return
                    raise
        except BitdefenderApiError as exc:
            if exc.name_conflict:
                _deployment_error(
                    "bitdefender_name_conflict",
                    error=(
                        f"a GravityZone rule named {compiled.name!r} already exists in the "
                        "company; deploy does not adopt it. Rename the block (name) or remove "
                        "the other rule"
                    ),
                    detail=str(exc),
                    **fields,
                )
            else:
                _deployment_error("bitdefender_request_failed", error=str(exc), **fields)
            return
        rule_id = returned_rule_id(result)
        if rule_id is None:
            _deployment_error(
                "bitdefender_create_no_id",
                error=(
                    f"createCustomRule for {compiled.name!r} answered {result!r}, not a 24-hex "
                    "rule id; the rule may exist on the tenant without a binding"
                ),
                **fields,
            )
            return
        logger.info("bitdefender_rule_created", uuid=object_uuid, rule_id=rule_id)
        try:
            record_created(
                object_uuid=object_uuid,
                platform=PLATFORM,
                tenant_name=tenant.name,
                external_id=rule_id,
            )
        except DeploymentStateError as error:
            report_failure(
                error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant.name
            )

    def _recreate(
        self,
        rule: DetectionRule,
        client: BitdefenderClient,
        tenant: BitdefenderTenant,
        compiled: GravityZoneRule,
        strategy: StatusStrategy,
        strategies: RunStrategies | None,
    ) -> None:
        """The bound rule is gone (``-32002``): create it again, or forget it under DISABLEMENT."""
        object_uuid = str(rule.metadata.uuid)
        if strategy is StatusStrategy.DISABLEMENT:
            _deployment_warning(
                "bitdefender_rule_missing",
                uuid=object_uuid,
                tenant=tenant.name,
                detail="the recorded rule no longer exists on the tenant; its id is removed",
            )
            self._forget(object_uuid, tenant)
            return
        _deployment_warning(
            "bitdefender_rule_recreated",
            uuid=object_uuid,
            tenant=tenant.name,
            detail="the recorded rule no longer exists on the tenant; creating it again",
        )
        ignore = deployment_state_ignore()
        refusal = (
            DeploymentStateError("deployment_state_ignored", ignored_message(ignore))
            if ignore is not None
            else unpersisted_error(
                object_uuid=object_uuid,
                platform=PLATFORM,
                tenant_name=tenant.name,
                strategies=strategies,
            )
        )
        if refusal is not None:
            report_failure(
                refusal, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant.name
            )
            return
        self._create(rule, client, tenant, compiled)

    @staticmethod
    def _forget(object_uuid: str, tenant: BitdefenderTenant) -> None:
        try:
            record_deleted(object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant.name)
        except DeploymentStateError as error:
            report_failure(
                error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant.name
            )

    # --- the run -------------------------------------------------------------------

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
    ) -> None:
        """Deploy *mdr_deployment* to every GravityZone tenant that accepts the run."""
        loaded: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded.append(mdr)
        loaded = without_legacy_external_ids(loaded, platform=PLATFORM)
        if not loaded:
            logger.info("no_rules_to_deploy_for_bitdefender")
            return
        deployment = TideDeployment(loaded, DetectionPlatforms.BITDEFENDER, strategies)
        for batch in deployment.rule_deployment:
            tenant = batch_tenant(batch, BitdefenderTenant)
            self.deploy_tenant(list(batch.rules), tenant, strategies)

    def deploy_tenant(
        self,
        rules: list[DetectionRule],
        tenant: BitdefenderTenant,
        strategies: RunStrategies | None,
        client: BitdefenderClient | None = None,
    ) -> None:
        """Every rule of *rules* on *tenant*, planned against deployment state first."""
        planned = screen_tenant(
            rules,
            platform=PLATFORM,
            tenant_name=tenant.name,
            status_of=lambda mdr: block_of(mdr).status,
            strategies=strategies,
        )
        if not planned:
            return
        if client is None:
            client = BitdefenderClient(
                tenant.setup.url,
                tenant.setup.api_key,
                tenant=tenant.name,
                key_type=tenant.setup.key_type,
                verify_ssl=tenant_tls_verify(
                    tenant.setup.ssl, platform=PLATFORM, tenant=tenant.name
                ),
            )
        for rule, action in planned:
            with deploy_events.deploying(PLATFORM, tenant.name, rule.metadata.uuid, rule.name):
                try:
                    self.deploy_rule(rule, client, tenant, action, strategies)
                except (BitdefenderTenantError, requests.RequestException) as exc:
                    # A refused key or an unreachable tenant fails every rule on it.
                    code = getattr(exc, "code", "bitdefender_tenant_unreachable")
                    logger.critical(
                        "bitdefender_tenant_deployment_failed",
                        code=code,
                        tenant=tenant.name,
                        error=str(exc),
                    )
                    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
                    deploy_events.note_failure(str(exc))
                    return


def declare() -> BitdefenderDeploy:
    """Entry point declared in pyproject.toml."""
    return BitdefenderDeploy()
