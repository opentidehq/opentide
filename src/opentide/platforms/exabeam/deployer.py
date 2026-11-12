"""Deploy correlation rules to Exabeam New-Scale SIEM (exabeam-1.0, Deploy).

Exabeam assigns every rule a UUID at create time. It is kept in
``.opentide/states/deployment/`` (deployment-state, RFC 0010), and every
create, update, disable and delete is planned from that shard before any
request: deploy never binds a rule it finds by listing, by ``nameContains`` or
by the ``opentide:`` marker. The one listing call, the name check before a
create, can only refuse the create (``exabeam_name_conflict``). Every update
sends the whole rule (``PUT`` replaces it), and ``DISABLEMENT`` is that same
``PUT`` with ``enabled: false``. A create that got no answer, or a ``5xx``,
is never sent again (``exabeam_create_unconfirmed``).
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
from opentide.platforms.exabeam.client import (
    ExabeamApiError,
    ExabeamClient,
    ExabeamTenantError,
)
from opentide.platforms.exabeam.compile import (
    ExabeamRule,
    block_of,
    compile_rule,
)
from opentide.platforms.exabeam.constraints import NAME_LIMIT
from opentide.platforms.plugins import RuleDeployer
from opentide.platforms.transport import tenant_tls_verify
from opentide.states.deployment import (
    DeploymentStateError,
    deployment_state_ignore,
    ignored_message,
)

logger = structlog.get_logger(__name__)
PLATFORM = "exabeam"

ExabeamTenant = ConfigurationModels.Systems.Exabeam.Tenant

_RULE_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)


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
    """The rule UUID a create answered, lower-case and canonical, or ``None``."""
    value = result.get("id") if isinstance(result, dict) else None
    if isinstance(value, str) and _RULE_ID.fullmatch(value.strip()):
        return value.strip().lower()
    return None


def name_matches(rules: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    """The rules *rules* holds whose name is *name*, compared case-insensitively and exactly.

    ``nameContains`` matches substrings, so its answer is filtered here.
    """
    wanted = name.casefold()
    return [rule for rule in rules if str(rule.get("name", "")).casefold() == wanted]


def schedule_retained(stored: dict[str, Any], compiled: ExabeamRule) -> bool:
    """Whether the rule a ``PUT`` returned keeps a schedule the block no longer sets."""
    if compiled.has_schedule:
        return False
    config = stored.get("scheduleConfig")
    if isinstance(config, dict):
        return bool(config.get("recurrences"))
    return bool(config)


def _rejected_detail(exc: ExabeamApiError) -> dict[str, Any]:
    """Exabeam's ``errors[]`` and ``traceId`` for the log line."""
    detail: dict[str, Any] = {}
    if exc.errors:
        detail["errors"] = [
            {key: entry.get(key) for key in ("code", "message", "fields") if key in entry}
            for entry in exc.errors
        ]
    if exc.trace_id:
        detail["trace_id"] = exc.trace_id
    return detail


class ExabeamDeploy(RuleDeployer):
    """Deploy rules to every Exabeam tenant a run reaches."""

    def compile_deployment(
        self,
        data: DetectionRule,
        tenant_config: Any | None = None,
        strategy: StatusStrategy | None = None,
    ) -> ExabeamRule:
        """What *data* deploys on *tenant_config* (no tenant: an offline preview)."""
        setup = tenant_config.setup if tenant_config is not None else None
        return compile_rule(data, strategy or _strategy(data), setup)

    def deploy_rule(
        self,
        rule: DetectionRule,
        client: ExabeamClient,
        tenant: Any,
        action: ExternalIdAction,
        strategies: RunStrategies | None = None,
    ) -> None:
        """Create, update, disable or delete one rule on one tenant.

        A rule-level failure is recorded and returns; :class:`ExabeamTenantError`
        (a refused key, no licence) and a request with no answer, other than a
        create, raise and stop the tenant.
        """
        object_uuid = str(rule.metadata.uuid)
        strategy = _strategy(rule)
        fields = {"uuid": object_uuid, "tenant": tenant.name, "name": rule.name}
        if action.kind == "delete":
            self._delete(object_uuid, client, tenant, action.known_id())
            return
        compiled = self.compile_deployment(rule, tenant, strategy)
        if len(compiled.name) > NAME_LIMIT:
            # validate reports it too; a deploy never sends a name Exabeam refuses.
            _deployment_error(
                "exabeam_name_length",
                error=(
                    f"the Exabeam rule name is {len(compiled.name)} characters, more than "
                    f"{NAME_LIMIT}: set a shorter configurations.exabeam.name"
                ),
                **fields,
            )
            return
        if action.kind == "create":
            self._create(rule, client, tenant, compiled)
            return
        rule_id = action.known_id()
        try:
            stored = client.update_rule(rule_id, compiled.body)
        except ExabeamApiError as exc:
            if exc.not_found:
                self._recreate(rule, client, tenant, compiled, strategy, strategies)
            else:
                self._request_failed(exc, **fields)
            return
        logger.info(
            "exabeam_rule_disabled"
            if strategy is StatusStrategy.DISABLEMENT
            else "exabeam_rule_updated",
            uuid=object_uuid,
            rule_id=rule_id,
        )
        if schedule_retained(stored, compiled):
            _deployment_warning(
                "exabeam_schedule_retained",
                detail=(
                    f"Exabeam rule {rule_id} keeps a schedule the block no longer sets; clear it "
                    "in the console"
                ),
                **fields,
            )
        if stored.get("autoDisabled") is True:
            _deployment_warning(
                "exabeam_rule_auto_disabled",
                detail=(
                    f"Exabeam stopped rule {rule_id} (autoDisabled): it matched or triggered too "
                    "often, or its query or context table is broken"
                ),
                **fields,
            )

    @staticmethod
    def _request_failed(exc: ExabeamApiError, **fields: Any) -> None:
        if exc.status == 400:
            _deployment_error(
                "exabeam_request_rejected", error=str(exc), **_rejected_detail(exc), **fields
            )
        else:
            _deployment_error("exabeam_request_failed", error=str(exc), **fields)

    def _delete(self, object_uuid: str, client: ExabeamClient, tenant: Any, rule_id: str) -> None:
        try:
            client.delete_rule(rule_id)
        except ExabeamApiError as exc:
            if not exc.not_found:
                self._request_failed(exc, uuid=object_uuid, tenant=tenant.name)
                return
        logger.info("exabeam_rule_deleted", uuid=object_uuid, rule_id=rule_id)
        self._forget(object_uuid, tenant)

    def _create(
        self,
        rule: DetectionRule,
        client: ExabeamClient,
        tenant: Any,
        compiled: ExabeamRule,
    ) -> None:
        object_uuid = str(rule.metadata.uuid)
        fields = {"uuid": object_uuid, "tenant": tenant.name, "name": compiled.name}
        try:
            existing = name_matches(client.rules_named(compiled.name), compiled.name)
        except ExabeamApiError as exc:
            self._request_failed(exc, **fields)
            return
        if existing:
            ids = ", ".join(str(item.get("id", "?")) for item in existing)
            _deployment_error(
                "exabeam_name_conflict",
                error=(
                    f"an Exabeam rule named {compiled.name!r} already exists (id {ids}); deploy "
                    "does not adopt it. Rename the block (name) or delete the other rule"
                ),
                existing_id=ids,
                **fields,
            )
            return
        unconfirmed = (
            f"the create of {compiled.name!r} got no answer, so Exabeam may have created it with "
            "an id opentide does not know; it is not sent again. Find the rule in the console: "
            "delete it, or record its id in .opentide/states/deployment/"
        )
        try:
            result = client.create_rule(compiled.body)
        except requests.RequestException as exc:
            _deployment_error(
                "exabeam_create_unconfirmed", error=unconfirmed, detail=str(exc), **fields
            )
            return
        except ExabeamApiError as exc:
            if exc.status >= 500:
                _deployment_error(
                    "exabeam_create_unconfirmed",
                    error=unconfirmed.replace("got no answer", f"got HTTP {exc.status}"),
                    detail=str(exc),
                    **fields,
                )
            else:
                self._request_failed(exc, **fields)
            return
        rule_id = returned_rule_id(result)
        if rule_id is None:
            _deployment_error(
                "exabeam_create_no_id",
                error=(
                    f"the create of {compiled.name!r} answered no rule UUID "
                    f"(id {result.get('id')!r}); the rule may exist on the tenant without a "
                    "binding: remove it in the console"
                ),
                **fields,
            )
            return
        logger.info("exabeam_rule_created", uuid=object_uuid, rule_id=rule_id)
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
        client: ExabeamClient,
        tenant: Any,
        compiled: ExabeamRule,
        strategy: StatusStrategy,
        strategies: RunStrategies | None,
    ) -> None:
        """The bound rule is gone (``PUT`` 404): create it again, or forget it under DISABLEMENT."""
        object_uuid = str(rule.metadata.uuid)
        if strategy is StatusStrategy.DISABLEMENT:
            _deployment_warning(
                "exabeam_rule_missing",
                uuid=object_uuid,
                tenant=tenant.name,
                detail="the recorded rule no longer exists on the tenant; its id is removed",
            )
            self._forget(object_uuid, tenant)
            return
        _deployment_warning(
            "exabeam_rule_recreated",
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
    def _forget(object_uuid: str, tenant: Any) -> None:
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
        """Deploy *mdr_deployment* to every Exabeam tenant that accepts the run."""
        loaded: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded.append(mdr)
        loaded = without_legacy_external_ids(loaded, platform=PLATFORM)
        if not loaded:
            logger.info("no_rules_to_deploy_for_exabeam")
            return
        deployment = TideDeployment(loaded, DetectionPlatforms.EXABEAM, strategies)
        for batch in deployment.rule_deployment:
            tenant = batch_tenant(batch, ExabeamTenant)
            self.deploy_tenant(list(batch.rules), tenant, strategies)

    def deploy_tenant(
        self,
        rules: list[DetectionRule],
        tenant: Any,
        strategies: RunStrategies | None,
        client: ExabeamClient | None = None,
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
            try:
                client = ExabeamClient(
                    tenant.setup.url,
                    tenant.setup.client_id,
                    tenant.setup.client_secret,
                    tenant=tenant.name,
                    verify_ssl=tenant_tls_verify(
                        tenant.setup.ssl, platform=PLATFORM, tenant=tenant.name
                    ),
                )
            except ValueError as exc:
                # An unset credential variable: no rule on the tenant can deploy.
                logger.critical(
                    "exabeam_tenant_deployment_failed", tenant=tenant.name, error=str(exc)
                )
                os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
                deploy_events.note_failure(str(exc))
                return
        for rule, action in planned:
            with deploy_events.deploying(PLATFORM, tenant.name, rule.metadata.uuid, rule.name):
                try:
                    self.deploy_rule(rule, client, tenant, action, strategies)
                except (ExabeamTenantError, ExabeamApiError, requests.RequestException) as exc:
                    # A refused key, no licence, a token that cannot be had, or an
                    # unreachable tenant fails every rule on it.
                    code = getattr(exc, "code", None)
                    if not isinstance(code, str):
                        code = "exabeam_tenant_unreachable"
                    logger.critical(
                        "exabeam_tenant_deployment_failed",
                        code=code,
                        tenant=tenant.name,
                        error=str(exc),
                    )
                    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
                    deploy_events.note_failure(str(exc))
                    return


def declare() -> ExabeamDeploy:
    """Entry point declared in pyproject.toml."""
    return ExabeamDeploy()
