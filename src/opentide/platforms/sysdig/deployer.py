"""Deploy Falco rules to Sysdig Secure (sysdig-1.0).

Custom Falco rules go through the Sysdig Secure runtime API. Sysdig assigns
every rule an integer id; it is kept in ``.opentide/states/deployment/``
(deployment-state, RFC 0010) and every create, update, disable and delete is
planned from that shard before any request. A rule alerts only when a runtime
policy names it: deploy adds it to the policies the block or the tenant names,
and never creates or deletes a policy.
"""

from __future__ import annotations

import os
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
from opentide.platforms.plugins import RuleDeployer
from opentide.platforms.sysdig.client import SysdigApiError, SysdigClient, SysdigTenantError
from opentide.platforms.sysdig.compile import FalcoRule, api_body, block_of, compile_rule
from opentide.platforms.transport import tenant_tls_verify
from opentide.states.deployment import (
    DeploymentStateError,
    deployment_state_ignore,
    ignored_message,
)

logger = structlog.get_logger(__name__)
PLATFORM = "sysdig"

SysdigTenant = ConfigurationModels.Systems.Sysdig.Tenant


def _deployment_error(event: str, **kwargs: Any) -> None:
    logger.error(event, **kwargs)
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    deploy_events.note_failure(str(kwargs.get("error") or event.replace("_", " ")))


def _deployment_warning(event: str, **kwargs: Any) -> None:
    logger.warning(event, **kwargs)
    os.environ["DEPLOYMENT_WARNING_RAISED"] = "1"


def _strategy(rule: DetectionRule) -> StatusStrategy:
    return check_status(block_of(rule).status)


class SysdigDeploy(RuleDeployer):
    """Deploy rules to every Sysdig tenant a run reaches."""

    def compile_deployment(
        self,
        data: DetectionRule,
        tenant_config: SysdigTenant | None = None,
        strategy: StatusStrategy | None = None,
    ) -> FalcoRule:
        """The Falco rule *data* deploys on *tenant_config*."""
        tags = tenant_config.setup.tags if tenant_config is not None else None
        return compile_rule(data, strategy or _strategy(data), tags)

    def deploy_api(
        self,
        rule: DetectionRule,
        client: SysdigClient,
        tenant: SysdigTenant,
        action: ExternalIdAction,
        strategies: RunStrategies | None = None,
    ) -> None:
        """Create, update, disable or delete one rule on an ``api`` tenant.

        A rule-level failure is recorded and returns; a refused token raises
        :class:`SysdigTenantError`, which stops the tenant.
        """
        object_uuid = str(rule.metadata.uuid)
        strategy = _strategy(rule)
        block = block_of(rule)
        compiled = self.compile_deployment(rule, tenant, strategy)
        policies = (
            []
            if compiled.tuning
            else list(block.policies if block.policies is not None else tenant.setup.policies or [])
        )
        try:
            if action.kind == "delete":
                if policies:
                    self._leave_policies(client, compiled.name, policies)
                client.delete_rule(action.known_id())
                self._forget(object_uuid, tenant)
                return
            if action.kind == "create":
                self._create(rule, client, tenant, compiled, policies)
                return
            rule_id = action.known_id()
            remote = client.get_rule(rule_id)
            if remote is None:
                self._recreate(rule, client, tenant, compiled, policies, strategy, strategies)
                return
            if strategy is StatusStrategy.DISABLEMENT and compiled.tuning:
                # A tuning cannot be disabled: it is removed, with its binding.
                client.delete_rule(rule_id)
                self._forget(object_uuid, tenant)
                return
            body = api_body(compiled)
            body["id"] = remote.get("id", int(rule_id))
            if "version" in remote:
                body["version"] = remote["version"]
            client.update_rule(rule_id, body)
            logger.info("sysdig_rule_updated", uuid=object_uuid, rule_id=rule_id)
            old_name = remote.get("name")
            if policies and isinstance(old_name, str) and old_name != compiled.name:
                self._rename_in_policies(client, old_name, compiled.name, policies)
            if strategy is StatusStrategy.DISABLEMENT:
                self._leave_policies(client, compiled.name, policies)
            else:
                self._join_policies(client, compiled.name, policies)
        except SysdigApiError as exc:
            _deployment_error(
                "sysdig_request_failed",
                uuid=object_uuid,
                tenant=tenant.name,
                status_code=exc.status_code,
                error=str(exc),
            )

    def _create(
        self,
        rule: DetectionRule,
        client: SysdigClient,
        tenant: SysdigTenant,
        compiled: FalcoRule,
        policies: Sequence[str],
    ) -> None:
        object_uuid = str(rule.metadata.uuid)
        created = client.create_rule(api_body(compiled))
        external_id = created.get("id")
        if external_id is None:
            raise SysdigApiError("create rule: the response carries no rule id")
        logger.info("sysdig_rule_created", uuid=object_uuid, rule_id=external_id)
        try:
            record_created(
                object_uuid=object_uuid,
                platform=PLATFORM,
                tenant_name=tenant.name,
                external_id=external_id,
            )
        except DeploymentStateError as error:
            report_failure(
                error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant.name
            )
        self._join_policies(client, compiled.name, policies)

    def _recreate(
        self,
        rule: DetectionRule,
        client: SysdigClient,
        tenant: SysdigTenant,
        compiled: FalcoRule,
        policies: Sequence[str],
        strategy: StatusStrategy,
        strategies: RunStrategies | None,
    ) -> None:
        """The bound rule is gone from Sysdig (404): create it again, as a create would."""
        object_uuid = str(rule.metadata.uuid)
        if strategy is StatusStrategy.DISABLEMENT:
            # Nothing exists to disable: forget the stale id rather than create a rule.
            _deployment_warning(
                "sysdig_rule_missing",
                uuid=object_uuid,
                tenant=tenant.name,
                detail="the recorded rule no longer exists on the tenant; its id is removed",
            )
            self._forget(object_uuid, tenant)
            return
        _deployment_warning(
            "sysdig_rule_recreated",
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
        self._create(rule, client, tenant, compiled, policies)

    @staticmethod
    def _forget(object_uuid: str, tenant: SysdigTenant) -> None:
        try:
            record_deleted(object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant.name)
        except DeploymentStateError as error:
            report_failure(
                error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant.name
            )

    # --- policies ----------------------------------------------------------------

    @staticmethod
    def _named(client: SysdigClient, names: Sequence[str]) -> list[dict[str, Any]]:
        """The named policies, or ``sysdig_policy_missing`` for the first one Sysdig lacks."""
        by_name = {str(p.get("name")): p for p in client.list_policies()}
        missing = [name for name in names if name not in by_name]
        if missing:
            raise SysdigApiError(
                f"sysdig_policy_missing: no runtime policy named {', '.join(map(repr, missing))} "
                f"on tenant {client.tenant}; create it in Sysdig Secure, or change the block's "
                "or the tenant's policies"
            )
        return [by_name[name] for name in names]

    def _join_policies(self, client: SysdigClient, rule_name: str, names: Sequence[str]) -> None:
        if not names:
            return
        for policy in self._named(client, names):
            rule_names = list(policy.get("ruleNames") or [])
            if rule_name in rule_names:
                continue
            client.update_policy({**policy, "ruleNames": [*rule_names, rule_name]})
            logger.info("sysdig_policy_rule_added", policy=policy.get("name"), rule=rule_name)

    def _leave_policies(self, client: SysdigClient, rule_name: str, names: Sequence[str]) -> None:
        if not names:
            return
        for policy in self._named(client, names):
            rule_names = list(policy.get("ruleNames") or [])
            if rule_name not in rule_names:
                continue
            kept = [name for name in rule_names if name != rule_name]
            client.update_policy({**policy, "ruleNames": kept})
            logger.info("sysdig_policy_rule_removed", policy=policy.get("name"), rule=rule_name)

    def _rename_in_policies(
        self, client: SysdigClient, old: str, new: str, names: Sequence[str]
    ) -> None:
        for policy in self._named(client, names):
            rule_names = list(policy.get("ruleNames") or [])
            if old not in rule_names:
                continue
            renamed = list(dict.fromkeys(new if name == old else name for name in rule_names))
            client.update_policy({**policy, "ruleNames": renamed})

    # --- the run -------------------------------------------------------------------

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
    ) -> None:
        """Deploy *mdr_deployment* to every Sysdig tenant that accepts the run."""
        loaded: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded.append(mdr)
        loaded = without_legacy_external_ids(loaded, platform=PLATFORM)
        if not loaded:
            logger.info("no_rules_to_deploy_for_sysdig")
            return
        deployment = TideDeployment(loaded, DetectionPlatforms.SYSDIG, strategies)
        for batch in deployment.rule_deployment:
            tenant = batch_tenant(batch, SysdigTenant)
            self._deploy_api_tenant(list(batch.rules), tenant, strategies)

    def _deploy_api_tenant(
        self,
        rules: list[DetectionRule],
        tenant: SysdigTenant,
        strategies: RunStrategies | None,
    ) -> None:
        # Plan against deployment state before the client exists: a refused
        # rule makes no request.
        planned = screen_tenant(
            rules,
            platform=PLATFORM,
            tenant_name=tenant.name,
            status_of=lambda mdr: block_of(mdr).status,
            strategies=strategies,
        )
        if not planned:
            return
        client = SysdigClient(
            tenant.setup.url,
            tenant.setup.api_token,
            tenant=tenant.name,
            verify_ssl=tenant_tls_verify(tenant.setup.ssl, platform=PLATFORM, tenant=tenant.name),
        )
        for rule, action in planned:
            with deploy_events.deploying(PLATFORM, tenant.name, rule.metadata.uuid, rule.name):
                try:
                    self.deploy_api(rule, client, tenant, action, strategies)
                except (SysdigTenantError, requests.RequestException) as exc:
                    # A refused token or an unreachable tenant fails every rule on it.
                    logger.critical(
                        "sysdig_tenant_deployment_failed", tenant=tenant.name, error=str(exc)
                    )
                    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
                    deploy_events.note_failure(str(exc))
                    return


def declare() -> SysdigDeploy:
    """Entry point declared in pyproject.toml."""
    return SysdigDeploy()
