"""Deploy event definitions to Graylog (graylog-1.0).

Graylog assigns every definition a 24-hex id at create time. It is kept in
``.opentide/states/deployment/`` (deployment-state), and every create, update,
disable and delete is planned from that shard before any request: deploy never
lists definitions nor finds one by title or tag. Deploy reads the server version
once per tenant, before any write, and builds every body for it. Before each
create and update, ``POST /api/search/validate`` checks the query; a query
Graylog reports as ``ERROR`` is never saved. Deploy never calls ``/execute``.
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
from opentide.platforms.graylog.client import (
    QUERY_INVALID,
    GraylogApiError,
    GraylogClient,
    GraylogTenantError,
    read_verdict,
    returned_id,
)
from opentide.platforms.graylog.compile import (
    ADVISORY,
    CompiledDefinition,
    GraylogAliasError,
    Version,
    block_of,
    compile_definition,
    create_body,
    is_vulnerable,
    update_body,
    validate_body,
    version_text,
)
from opentide.platforms.plugins import RuleDeployer
from opentide.platforms.transport import tenant_tls_verify
from opentide.states.deployment import (
    DeploymentStateError,
    deployment_state_ignore,
    ignored_message,
)

logger = structlog.get_logger(__name__)
PLATFORM = "graylog"

GraylogTenant = ConfigurationModels.Systems.Graylog.Tenant


def _deployment_error(code: str, **kwargs: Any) -> None:
    logger.error(code, code=code, **kwargs)
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    deploy_events.note_failure(f"{code}: {kwargs.get('error') or code.replace('_', ' ')}")


def _deployment_warning(code: str, **kwargs: Any) -> None:
    logger.warning(code, code=code, **kwargs)
    os.environ["DEPLOYMENT_WARNING_RAISED"] = "1"


def _strategy(rule: DetectionRule) -> StatusStrategy:
    return check_status(block_of(rule).status)


def _api_failure(exc: GraylogApiError, **fields: Any) -> None:
    """The code of a refused request (graylog-1.0, the failure table), recorded for the rule."""
    if exc.immutable:
        _deployment_error(
            "graylog_definition_immutable",
            error=f"{exc.detail}; deploy never changes a definition's scope",
            **fields,
        )
    elif exc.in_use:
        _deployment_error(
            "graylog_definition_in_use",
            error=f"another definition depends on this one: {exc.detail}",
            **fields,
        )
    elif exc.forbidden:
        _deployment_error(
            "graylog_forbidden",
            error=(
                f"{exc.method} {exc.path} was refused (HTTP 403): {exc.detail}. The token's user "
                "needs eventdefinitions:create, read, edit and delete, and streams:read on every "
                "stream the definition names"
            ),
            **fields,
        )
    elif exc.invalid:
        _deployment_error("graylog_definition_invalid", error=exc.detail, **fields)
    else:
        _deployment_error("graylog_request_failed", error=str(exc), **fields)


class GraylogDeploy(RuleDeployer):
    """Deploy rules to every Graylog tenant a run reaches."""

    def compile_deployment(
        self,
        data: DetectionRule,
        tenant_config: GraylogTenant | None = None,
        version: Version | None = None,
    ) -> CompiledDefinition:
        """What *data* deploys on *tenant_config* at *version* (no tenant: an offline preview).

        Without *version*, the body is built for the newest supported line (7.2).
        """
        from opentide.platforms.graylog.compile import PREVIEW_VERSION

        setup = tenant_config.setup if tenant_config is not None else None
        tenant = tenant_config.name if tenant_config is not None else None
        return compile_definition(data, version or PREVIEW_VERSION, setup, tenant=tenant)

    def deploy_rule(
        self,
        rule: DetectionRule,
        client: GraylogClient,
        tenant: GraylogTenant,
        action: ExternalIdAction,
        strategies: RunStrategies | None = None,
    ) -> None:
        """Create, update, disable or delete one definition on one tenant.

        A rule-level failure is recorded and returns; a refused token raises
        :class:`GraylogTenantError`, which stops the tenant.
        """
        object_uuid = str(rule.metadata.uuid)
        strategy = _strategy(rule)
        fields = {"uuid": object_uuid, "tenant": tenant.name, "name": rule.name}
        if action.kind == "delete":
            self._delete(object_uuid, client, tenant, action.known_id())
            return
        version = client.version()
        try:
            compiled = self.compile_deployment(rule, tenant, version)
        except GraylogAliasError as exc:
            _deployment_error(exc.code, error=exc.reason, **fields)
            return
        for code, message in compiled.warnings:
            _deployment_warning(code, detail=message, **fields)
        if not self._query_accepted(client, compiled, **fields):
            return
        if action.kind == "create":
            self._create(client, tenant, compiled)
            return
        definition_id = action.known_id()
        enabled = strategy is not StatusStrategy.DISABLEMENT
        try:
            client.update(definition_id, update_body(compiled, definition_id), enabled=enabled)
        except GraylogApiError as exc:
            if exc.not_found:
                self._recreate(rule, client, tenant, compiled, strategy, strategies)
            else:
                _api_failure(exc, **fields)
            return
        logger.info(
            "graylog_definition_updated",
            uuid=object_uuid,
            definition_id=definition_id,
            scheduled=enabled,
        )

    def _query_accepted(
        self, client: GraylogClient, compiled: CompiledDefinition, **fields: Any
    ) -> bool:
        """Graylog's verdict on the query, before anything is saved: ``False`` on ``ERROR``."""
        try:
            verdict = client.validate_query(validate_body(compiled))
        except GraylogApiError as exc:
            _api_failure(exc, **fields)
            return False
        errors, warnings = read_verdict(verdict)
        for code, message in warnings:
            _deployment_warning(code, detail=message, **fields)
        if errors:
            _deployment_error(
                QUERY_INVALID,
                error=f"Graylog refuses the query, so nothing is saved: {'; '.join(errors)}",
                **fields,
            )
            return False
        return True

    def _delete(
        self, object_uuid: str, client: GraylogClient, tenant: GraylogTenant, definition_id: str
    ) -> None:
        try:
            client.delete(definition_id)
        except GraylogApiError as exc:
            _api_failure(exc, uuid=object_uuid, tenant=tenant.name, definition_id=definition_id)
            return
        logger.info("graylog_definition_deleted", uuid=object_uuid, definition_id=definition_id)
        self._forget(object_uuid, tenant)

    def _create(
        self, client: GraylogClient, tenant: GraylogTenant, compiled: CompiledDefinition
    ) -> None:
        object_uuid = compiled.uuid
        fields = {"uuid": object_uuid, "tenant": tenant.name, "name": compiled.title}
        try:
            answer = client.create(create_body(compiled))
        except requests.RequestException as exc:
            # No answer: the create may have happened. Titles are not unique, so a
            # retry could create a second definition; it is never retried.
            found_by = f"the title {compiled.title!r}"
            if compiled.uuid_tag:
                found_by += f" or the tag {compiled.uuid_tag!r}"
            _deployment_error(
                "graylog_create_unconfirmed",
                error=(
                    f"the create got no answer, so it may have succeeded with an id opentide does "
                    f"not know. Find the definition by {found_by} in Graylog, then delete it or "
                    "record its id in .opentide/states/deployment/"
                ),
                detail=str(exc),
                **fields,
            )
            return
        except GraylogApiError as exc:
            _api_failure(exc, **fields)
            return
        definition_id = returned_id(answer)
        if definition_id is None:
            _deployment_error(
                "graylog_create_unconfirmed",
                error=(
                    f"the create of {compiled.title!r} answered no 24-hex id, so the definition "
                    "may exist without a binding; find it in Graylog, then delete it or record "
                    "its id in .opentide/states/deployment/"
                ),
                **fields,
            )
            return
        logger.info("graylog_definition_created", uuid=object_uuid, definition_id=definition_id)
        try:
            record_created(
                object_uuid=object_uuid,
                platform=PLATFORM,
                tenant_name=tenant.name,
                external_id=definition_id,
            )
        except DeploymentStateError as error:
            report_failure(
                error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant.name
            )

    def _recreate(
        self,
        rule: DetectionRule,
        client: GraylogClient,
        tenant: GraylogTenant,
        compiled: CompiledDefinition,
        strategy: StatusStrategy,
        strategies: RunStrategies | None,
    ) -> None:
        """The bound definition is gone (404): create it again, or forget it under DISABLEMENT."""
        object_uuid = str(rule.metadata.uuid)
        if strategy is StatusStrategy.DISABLEMENT:
            _deployment_warning(
                "graylog_definition_missing",
                uuid=object_uuid,
                tenant=tenant.name,
                detail="the recorded definition no longer exists on the tenant; its id is removed",
            )
            self._forget(object_uuid, tenant)
            return
        _deployment_warning(
            "graylog_definition_recreated",
            uuid=object_uuid,
            tenant=tenant.name,
            detail="the recorded definition no longer exists on the tenant; creating it again",
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
        self._create(client, tenant, compiled)

    @staticmethod
    def _forget(object_uuid: str, tenant: GraylogTenant) -> None:
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
        """Deploy *mdr_deployment* to every Graylog tenant that accepts the run."""
        loaded: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded.append(mdr)
        loaded = without_legacy_external_ids(loaded, platform=PLATFORM)
        if not loaded:
            logger.info("no_rules_to_deploy_for_graylog")
            return
        deployment = TideDeployment(loaded, DetectionPlatforms.GRAYLOG, strategies)
        for batch in deployment.rule_deployment:
            tenant = batch_tenant(batch, GraylogTenant)
            self.deploy_tenant(list(batch.rules), tenant, strategies)

    @staticmethod
    def _tenant_failed(tenant: GraylogTenant, code: str | None, error: str) -> None:
        logger.critical(
            "graylog_tenant_deployment_failed", code=code, tenant=tenant.name, error=error
        )
        os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
        deploy_events.note_failure(error)

    def _checked_version(self, client: GraylogClient, tenant: GraylogTenant) -> bool:
        """Read the version once, before any write; warn on an affected one. ``False`` stops."""
        try:
            version = client.version()
        except GraylogTenantError as exc:
            self._tenant_failed(tenant, exc.code, str(exc))
            return False
        except GraylogApiError as exc:
            code = "graylog_forbidden" if exc.forbidden else "graylog_request_failed"
            self._tenant_failed(tenant, code, f"{code}: {exc}")
            return False
        except requests.RequestException as exc:
            self._tenant_failed(tenant, "graylog_tenant_unreachable", str(exc))
            return False
        if is_vulnerable(version):
            _deployment_warning(
                "graylog_version_vulnerable",
                tenant=tenant.name,
                detail=(
                    f"Graylog {version_text(version)} does not revoke access tokens reliably "
                    f"({ADVISORY}); upgrade to 6.3.12, 7.0.16, 7.1.12 or later"
                ),
            )
        return True

    def deploy_tenant(
        self,
        rules: list[DetectionRule],
        tenant: GraylogTenant,
        strategies: RunStrategies | None,
        client: GraylogClient | None = None,
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
                client = GraylogClient(
                    tenant.setup.url,
                    tenant.setup.token,
                    tenant=tenant.name,
                    verify_ssl=tenant_tls_verify(
                        tenant.setup.ssl, platform=PLATFORM, tenant=tenant.name
                    ),
                )
            except ValueError as exc:
                # An unset credential variable: no rule on the tenant can deploy.
                self._tenant_failed(tenant, None, str(exc))
                return
        if not self._checked_version(client, tenant):
            return
        for rule, action in planned:
            with deploy_events.deploying(PLATFORM, tenant.name, rule.metadata.uuid, rule.name):
                try:
                    self.deploy_rule(rule, client, tenant, action, strategies)
                except GraylogTenantError as exc:
                    # A refused token fails every rule on the tenant.
                    self._tenant_failed(tenant, exc.code, str(exc))
                    return
                except requests.RequestException as exc:
                    self._tenant_failed(tenant, "graylog_tenant_unreachable", str(exc))
                    return


def declare() -> GraylogDeploy:
    """Entry point declared in pyproject.toml."""
    return GraylogDeploy()
