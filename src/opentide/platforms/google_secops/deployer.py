"""Deploy YARA-L rules to Google Security Operations (google-secops-1.0).

Google assigns every rule an id (``ru_<uuid>``) at create time. It is kept in
``.opentide/states/deployment/`` (deployment-state), and every create, update,
disable, archive and delete is planned from that shard before any request:
deploy never lists rules nor finds one by name or meta. Each create and each
text update is compiled by ``verifyRuleText`` first; an unchanged text is never
sent again, so the rule keeps its revision. The run state follows the status
strategy: ``PREVIEW`` runs the rule without alerting, ``RELEASE`` and
``UNIVERSAL`` alert, ``DISABLEMENT`` disables it, and ``DELETION`` archives
it, or deletes it without ``force`` when the tenant asks: deploy never deletes
a rule's detections.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
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
from opentide.models.platform import GoogleSecopsConfig
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, batch_tenant
from opentide.platforms.google_secops.client import (
    GoogleSecopsApiError,
    GoogleSecopsClient,
    GoogleSecopsTenantError,
)
from opentide.platforms.google_secops.compile import (
    DISABLED,
    AssembledRule,
    GoogleSecopsCompileError,
    assemble,
    block_of,
    preferred_frequency,
    run_state,
)
from opentide.platforms.google_secops.diagnostics import (
    VerifyOutcome,
    describe_diagnostic,
    read_verify_answer,
)
from opentide.platforms.plugins import RuleDeployer
from opentide.states.deployment import (
    DeploymentStateError,
    deployment_state_ignore,
    ignored_message,
)

logger = structlog.get_logger(__name__)
PLATFORM = "google_secops"

GoogleSecopsTenant = ConfigurationModels.Systems.GoogleSecops.Tenant

#: The rule id at the end of a rule resource ``name``.
_RULE_ID = re.compile(r"(?:^|/)(ru_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
#: Errors that mean the request never reached Google: nothing can have been created.
_NOT_SENT = (
    requests.exceptions.ConnectTimeout,
    requests.exceptions.ProxyError,
    requests.exceptions.SSLError,
    requests.exceptions.InvalidURL,
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


def returned_rule_id(name: object) -> str | None:
    """The ``ru_<uuid>`` id at the end of a rule resource *name*, or ``None``."""
    if not isinstance(name, str):
        return None
    found = _RULE_ID.search(name.strip())
    return found.group(1) if found else None


class GoogleSecopsDeploy(RuleDeployer):
    """Deploy rules to every Google SecOps instance a run reaches."""

    def compile_deployment(
        self,
        data: DetectionRule,
        tenant_config: Any = None,
        strategy: StatusStrategy | None = None,
    ) -> AssembledRule:
        """The YARA-L text *data* deploys; the same on every tenant."""
        del tenant_config, strategy
        return assemble(data)

    def deploy_rule(
        self,
        rule: DetectionRule,
        client: GoogleSecopsClient,
        tenant: Any,
        action: ExternalIdAction,
        strategies: RunStrategies | None = None,
    ) -> None:
        """Create, update, disable, archive or delete one rule on one tenant.

        A rule-level failure is recorded and returns; refused credentials raise
        :class:`GoogleSecopsTenantError`, and a tenant that does not answer a
        :class:`requests.RequestException`, either of which stops the tenant.
        """
        strategy = _strategy(rule)
        if action.kind == "delete":
            self._retire(rule, client, tenant, action.known_id())
            return
        block = block_of(rule)
        fields = _fields(rule, tenant)
        try:
            assembled = assemble(rule, block)
        except GoogleSecopsCompileError as exc:
            _deployment_error("compile_failed", error=str(exc), **fields)
            return
        if action.kind == "create":
            self._create(rule, client, tenant, block, assembled, strategy)
            return
        self._update(
            rule, client, tenant, block, assembled, strategy, action.known_id(), strategies
        )

    # --- verify --------------------------------------------------------------------

    def _verify(
        self, client: GoogleSecopsClient, assembled: AssembledRule, fields: Mapping[str, Any]
    ) -> VerifyOutcome | None:
        """``verifyRuleText`` on *assembled*; ``None`` (and the rule failed) when it does not."""
        try:
            outcome = read_verify_answer(client.verify(assembled.text))
        except GoogleSecopsApiError as exc:
            _request_failed(exc, fields)
            return None
        for warning in outcome.warnings:
            logger.warning(
                "google_secops_compile_warning",
                code="google_secops_compile_warning",
                detail=describe_diagnostic(warning, assembled),
                **fields,
            )
        if outcome.ok:
            return outcome
        reasons = [describe_diagnostic(item, assembled) for item in outcome.errors] or [
            "verifyRuleText did not report success"
        ]
        _deployment_error(
            "google_secops_verify_failed",
            error=f"Google SecOps does not compile rule {assembled.name}: {'; '.join(reasons)}",
            **fields,
        )
        return None

    @staticmethod
    def _frequency(
        block: GoogleSecopsConfig,
        allowed: Sequence[str],
        fields: Mapping[str, Any],
    ) -> tuple[bool, str | None]:
        """Whether the rule may go on, and the run frequency to send."""
        if block.run_frequency:
            if allowed and block.run_frequency not in allowed:
                _deployment_error(
                    "google_secops_run_frequency_not_allowed",
                    error=(
                        f"run_frequency {block.run_frequency} is not one Google allows for this "
                        f"rule ({', '.join(allowed)}); nothing was written"
                    ),
                    **fields,
                )
                return False, None
            return True, block.run_frequency
        return True, preferred_frequency(allowed)

    # --- create --------------------------------------------------------------------

    def _create(
        self,
        rule: DetectionRule,
        client: GoogleSecopsClient,
        tenant: Any,
        block: GoogleSecopsConfig,
        assembled: AssembledRule,
        strategy: StatusStrategy,
    ) -> None:
        object_uuid = str(rule.metadata.uuid)
        fields = _fields(rule, tenant)
        try:
            outcome = self._verify(client, assembled, fields)
            if outcome is None:
                return
            proceed, frequency = self._frequency(block, outcome.allowed, fields)
            if not proceed:
                return
            try:
                created = client.create(
                    assembled.text, client.scope_resource(tenant.setup.data_access_scope)
                )
            except _NOT_SENT:
                raise
            except requests.RequestException as exc:
                # No answer: the rule may exist with an id opentide never saw.
                _deployment_error(
                    "google_secops_create_unconfirmed",
                    error=(
                        f"the create of rule {assembled.name} got no answer ({exc}), so it may "
                        "have succeeded with an id opentide does not know. Deploy does not send "
                        "it again: find the rule in Google SecOps (Detection, Rules) and delete "
                        "it, or record its ru_ id in .opentide/states/deployment/"
                    ),
                    **fields,
                )
                return
        except GoogleSecopsApiError as exc:
            _request_failed(exc, fields)
            return
        rule_id = returned_rule_id(created.get("name"))
        if rule_id is None:
            _deployment_error(
                "google_secops_create_no_id",
                error=(
                    f"rules.create for {assembled.name} answered name {created.get('name')!r}, "
                    "which does not end in a rule id; the rule may exist without a binding"
                ),
                **fields,
            )
            return
        logger.info("google_secops_rule_created", uuid=object_uuid, rule_id=rule_id)
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
            return
        self._run_state(client, rule_id, block, strategy, frequency, fields, created=True)

    # --- update --------------------------------------------------------------------

    def _update(
        self,
        rule: DetectionRule,
        client: GoogleSecopsClient,
        tenant: Any,
        block: GoogleSecopsConfig,
        assembled: AssembledRule,
        strategy: StatusStrategy,
        rule_id: str,
        strategies: RunStrategies | None,
    ) -> None:
        fields = {**_fields(rule, tenant), "rule_id": rule_id}
        try:
            remote = client.get_rule(rule_id)
        except GoogleSecopsApiError as exc:
            if exc.not_found:
                self._gone(rule, client, tenant, block, assembled, strategy, strategies)
            else:
                _request_failed(exc, fields)
            return
        allowed = [str(item) for item in remote.get("allowedRunFrequencies") or []]
        changed = remote.get("text") != assembled.text
        if changed:
            outcome = self._verify(client, assembled, fields)
            if outcome is None:
                return
            allowed = list(outcome.allowed) or allowed
        frequency: str | None = None
        if strategy is not StatusStrategy.DISABLEMENT:
            proceed, frequency = self._frequency(block, allowed, fields)
            if not proceed:
                return
        if changed:
            try:
                client.update_text(
                    rule_id,
                    assembled.text,
                    _etag(remote),
                    client.scope_resource(tenant.setup.data_access_scope),
                )
            except GoogleSecopsApiError as exc:
                if exc.not_found:
                    self._gone(rule, client, tenant, block, assembled, strategy, strategies)
                elif exc.conflict:
                    _deployment_error(
                        "google_secops_rule_conflict",
                        error=(
                            f"rule {rule_id} changed between its read and the update (etag "
                            "mismatch); nothing was written. Deploy again"
                        ),
                        detail=str(exc),
                        **fields,
                    )
                else:
                    _request_failed(exc, fields)
                return
            logger.info("google_secops_rule_updated", uuid=str(rule.metadata.uuid), rule_id=rule_id)
        self._run_state(client, rule_id, block, strategy, frequency, fields, created=False)

    def _run_state(
        self,
        client: GoogleSecopsClient,
        rule_id: str,
        block: GoogleSecopsConfig,
        strategy: StatusStrategy,
        frequency: str | None,
        fields: Mapping[str, Any],
        *,
        created: bool,
    ) -> None:
        """Bring the rule's deployment to what *strategy* runs; a failure keeps the binding."""
        state = run_state(block, strategy, frequency)
        try:
            if created:
                client.update_deployment(rule_id, state.mask, state.body)
                return
            remote = client.get_deployment(rule_id)
            if strategy is StatusStrategy.DISABLEMENT:
                # An archived rule is disabled already, and takes no other change.
                if not remote.get("archived") and state.differs_from(remote):
                    client.update_deployment(rule_id, state.mask, state.body)
                return
            if remote.get("archived"):
                client.update_deployment(rule_id, "archived", {"archived": False})
                remote = {**remote, "archived": False}
            if state.differs_from(remote):
                client.update_deployment(rule_id, state.mask, state.body)
        except GoogleSecopsApiError as exc:
            _deployment_error(
                "google_secops_deployment_failed",
                error=(
                    f"rule {rule_id} is bound, but its run state could not be set ({exc}); the "
                    "next deploy repairs it"
                ),
                **{**fields, "rule_id": rule_id},
            )

    def _gone(
        self,
        rule: DetectionRule,
        client: GoogleSecopsClient,
        tenant: Any,
        block: GoogleSecopsConfig,
        assembled: AssembledRule,
        strategy: StatusStrategy,
        strategies: RunStrategies | None,
    ) -> None:
        """The bound rule no longer exists: create it again, or forget it when retiring it."""
        object_uuid = str(rule.metadata.uuid)
        if strategy in (StatusStrategy.DISABLEMENT, StatusStrategy.DELETION):
            _deployment_warning(
                "google_secops_rule_missing",
                uuid=object_uuid,
                tenant=tenant.name,
                detail="the recorded rule no longer exists on the instance; its id is removed",
            )
            self._forget(object_uuid, tenant)
            return
        _deployment_warning(
            "google_secops_rule_recreated",
            uuid=object_uuid,
            tenant=tenant.name,
            detail="the recorded rule no longer exists on the instance; creating it again",
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
        self._create(rule, client, tenant, block, assembled, strategy)

    # --- DELETION ------------------------------------------------------------------

    def _retire(
        self, rule: DetectionRule, client: GoogleSecopsClient, tenant: Any, rule_id: str
    ) -> None:
        """``DELETION``: archive the rule, or delete it without ``force`` (google-secops-1.0)."""
        object_uuid = str(rule.metadata.uuid)
        fields = {**_fields(rule, tenant), "rule_id": rule_id}
        if tenant.setup.deletion != "delete":
            self._archive(object_uuid, client, tenant, rule_id, fields)
            return
        try:
            client.delete(rule_id)
        except GoogleSecopsApiError as exc:
            if exc.failed_precondition:
                _deployment_warning(
                    "google_secops_delete_refused",
                    detail=(
                        f"Google refused to delete rule {rule_id} because it has detections or "
                        "retrohunts; it is archived instead and keeps its binding"
                    ),
                    error=str(exc),
                    **fields,
                )
                self._archive(object_uuid, client, tenant, rule_id, fields)
                return
            if not exc.not_found:
                _request_failed(exc, fields)
                return
        logger.info("google_secops_rule_deleted", uuid=object_uuid, rule_id=rule_id)
        self._forget(object_uuid, tenant)

    def _archive(
        self,
        object_uuid: str,
        client: GoogleSecopsClient,
        tenant: Any,
        rule_id: str,
        fields: Mapping[str, Any],
    ) -> None:
        try:
            remote = client.get_deployment(rule_id)
            if remote.get("archived"):
                logger.info(
                    "google_secops_rule_archived_already", uuid=object_uuid, rule_id=rule_id
                )
                return
            if DISABLED.differs_from(remote):
                client.update_deployment(rule_id, DISABLED.mask, DISABLED.body)
            client.update_deployment(rule_id, "archived", {"archived": True})
        except GoogleSecopsApiError as exc:
            if exc.not_found:
                _deployment_warning(
                    "google_secops_rule_missing",
                    detail="the recorded rule no longer exists on the instance; its id is removed",
                    **fields,
                )
                self._forget(object_uuid, tenant)
            else:
                _request_failed(exc, fields)
            return
        logger.info("google_secops_rule_archived", uuid=object_uuid, rule_id=rule_id)

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
        """Deploy *mdr_deployment* to every Google SecOps instance that accepts the run."""
        loaded: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded.append(mdr)
        loaded = without_legacy_external_ids(loaded, platform=PLATFORM)
        if not loaded:
            logger.info("no_rules_to_deploy_for_google_secops")
            return
        deployment = TideDeployment(loaded, DetectionPlatforms.GOOGLE_SECOPS, strategies)
        for batch in deployment.rule_deployment:
            tenant = batch_tenant(batch, GoogleSecopsTenant)
            self.deploy_tenant(list(batch.rules), tenant, strategies)

    def deploy_tenant(
        self,
        rules: list[DetectionRule],
        tenant: Any,
        strategies: RunStrategies | None,
        client: GoogleSecopsClient | None = None,
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
                client = GoogleSecopsClient.for_tenant(tenant)
            except (ValueError, GoogleSecopsTenantError) as exc:
                # Unset or unreadable credentials: no rule on the tenant can deploy.
                _tenant_failed(tenant, exc)
                return
        for rule, action in planned:
            with deploy_events.deploying(PLATFORM, tenant.name, rule.metadata.uuid, rule.name):
                try:
                    self.deploy_rule(rule, client, tenant, action, strategies)
                except (GoogleSecopsTenantError, requests.RequestException) as exc:
                    # Refused credentials or an unreachable instance fail every rule on it.
                    _tenant_failed(tenant, exc)
                    return


def _fields(rule: DetectionRule, tenant: Any) -> dict[str, Any]:
    return {"uuid": str(rule.metadata.uuid), "tenant": tenant.name, "name": rule.name}


def _etag(remote: Mapping[str, Any]) -> str | None:
    etag = remote.get("etag")
    return str(etag) if etag else None


def _request_failed(exc: GoogleSecopsApiError, fields: Mapping[str, Any]) -> None:
    _deployment_error(
        "google_secops_request_failed",
        error=f"{exc.status or f'HTTP {exc.http_status}'}: {exc.message}",
        detail=str(exc),
        **fields,
    )


def _tenant_failed(tenant: Any, exc: BaseException) -> None:
    code = getattr(exc, "code", None)
    if not isinstance(code, str):
        code = "google_secops_tenant_unreachable"
    logger.critical(
        "google_secops_tenant_deployment_failed", code=code, tenant=tenant.name, error=str(exc)
    )
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    deploy_events.note_failure(str(exc))


def declare() -> GoogleSecopsDeploy:
    """Entry point declared in pyproject.toml."""
    return GoogleSecopsDeploy()
