"""``validate query --platform google_secops --live``: Google's own compiler (google-secops-1.0).

Each rule's assembled YARA-L text is sent to ``verifyRuleText`` on every
instance deploy would send it to. The call compiles the rule, resolving the
instance's reference lists and data tables, and creates, updates and runs
nothing. Google's ``ERROR`` diagnostics fail the rule as
``google_secops_compile_error`` and its ``WARNING`` diagnostics are
``google_secops_compile_warning``, each placed on the section key and line it
falls in; a block ``run_frequency`` Google does not allow for the rule is
``google_secops_run_frequency_not_allowed``. Refused credentials fail the
instance.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, ClassVar

import structlog

from opentide.models.deployment_enums import RunStrategies
from opentide.models.rule import DetectionRule
from opentide.platforms.google_secops.client import (
    GoogleSecopsApiError,
    GoogleSecopsClient,
    GoogleSecopsTenantError,
)
from opentide.platforms.google_secops.compile import (
    GoogleSecopsCompileError,
    assemble,
    default_endpoint,
)
from opentide.platforms.google_secops.diagnostics import describe_diagnostic, read_verify_answer
from opentide.platforms.live_validation import TimeoutStreak, timeout_text
from opentide.platforms.plugins import QueryValidator, resolve_rules
from opentide.query.check import QUERY_CHECK_TIMEOUT, LiveCheckReport, RuleCheck, check_timeout

logger = structlog.get_logger(__name__)

PLATFORM = "google_secops"
COMPILE_ERROR = "google_secops_compile_error"
COMPILE_WARNING = "google_secops_compile_warning"
FREQUENCY_NOT_ALLOWED = "google_secops_run_frequency_not_allowed"

ClientFactory = Callable[[Any, float], GoogleSecopsClient]


def _client(tenant: Any, timeout: float) -> GoogleSecopsClient:
    return GoogleSecopsClient.for_tenant(tenant, timeout=timeout)


def check_rule(rule: DetectionRule, client: GoogleSecopsClient, tenant_name: str) -> RuleCheck:
    """*rule*'s assembled text, compiled by ``verifyRuleText`` on one instance.

    Raises :class:`GoogleSecopsTenantError` when the instance refuses the
    credentials, and lets a transport failure through.
    """
    uuid = str(rule.metadata.uuid)
    try:
        assembled = assemble(rule)
    except GoogleSecopsCompileError as exc:
        return RuleCheck(rule=uuid, name=rule.name, tenant=tenant_name, errors=(str(exc),))
    try:
        outcome = read_verify_answer(client.verify(assembled.text))
    except GoogleSecopsApiError as exc:
        return RuleCheck(
            rule=uuid,
            name=rule.name,
            tenant=tenant_name,
            errors=(f"verifyRuleText failed: {exc.status or exc.http_status}: {exc.message}",),
        )
    errors = [f"{COMPILE_ERROR}: {describe_diagnostic(item, assembled)}" for item in outcome.errors]
    if not outcome.success and not errors:
        errors.append(f"{COMPILE_ERROR}: verifyRuleText did not report success")
    block = rule.platform_configs().google_secops
    frequency = block.run_frequency if block is not None else None
    if frequency and outcome.allowed and frequency not in outcome.allowed:
        errors.append(
            f"{FREQUENCY_NOT_ALLOWED}: configurations.google_secops.run_frequency {frequency} "
            f"is not one Google allows for this rule ({', '.join(outcome.allowed)})"
        )
    warnings = tuple(
        f"{COMPILE_WARNING}: {describe_diagnostic(item, assembled)}" for item in outcome.warnings
    )
    for error in errors:
        logger.critical(
            "query_rejected",
            detail=f"{rule.name} ({uuid}) on {PLATFORM} tenant {tenant_name}",
            reason=error,
        )
    return RuleCheck(
        rule=uuid, name=rule.name, tenant=tenant_name, errors=tuple(errors), warnings=warnings
    )


class GoogleSecopsValidator(QueryValidator):
    """Compile rules with ``verifyRuleText`` on their Google SecOps instances."""

    platform: ClassVar[str] = PLATFORM

    def __init__(self, client_factory: ClientFactory | None = None) -> None:
        self._client_factory = client_factory or _client

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
        *,
        timeout: float | None = None,
    ) -> LiveCheckReport:
        from opentide.deployment import TideDeployment
        from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES, DetectionPlatforms
        from opentide.models.system_config import ConfigurationModels, batch_tenant
        from opentide.platforms.transport import reaching_tenant, read_timeout

        seconds = check_timeout(timeout)
        deployment = TideDeployment(
            deployment=resolve_rules(mdr_deployment),
            system=DetectionPlatforms.GOOGLE_SECOPS,
            strategies=strategies or DEPLOYABLE_STRATEGIES,
        )
        report = LiveCheckReport(PLATFORM, timeout=seconds)
        for batch in deployment.rule_deployment:
            tenant = batch_tenant(batch, ConfigurationModels.Systems.GoogleSecops.Tenant)
            host = tenant.setup.endpoint or default_endpoint(tenant.setup.location)
            rules = [rule for rule in batch.rules if rule.platform_configs().google_secops]
            if not rules:
                continue
            try:
                client = self._client_factory(tenant, seconds)
            except GoogleSecopsTenantError as exc:
                report.checks.extend(_failed(rule, tenant.name, str(exc)) for rule in rules)
                continue
            streak = TimeoutStreak(PLATFORM, tenant.name, host, seconds)
            with reaching_tenant(PLATFORM, tenant.name, host):
                for rule in rules:
                    try:
                        check = check_rule(rule, client, tenant.name)
                    except GoogleSecopsTenantError as exc:
                        streak.answered()
                        # The instance refuses every rule alike: the rest are not sent.
                        logger.critical(
                            "google_secops_tenant_validation_failed",
                            tenant=tenant.name,
                            error=str(exc),
                        )
                        report.checks.append(_failed(rule, tenant.name, str(exc)))
                        break
                    except Exception as exc:
                        error = read_timeout(exc)
                        if error is None:
                            raise
                        streak.timed_out(error)
                        report.checks.append(
                            RuleCheck(
                                rule=str(rule.metadata.uuid),
                                name=rule.name,
                                tenant=tenant.name,
                                errors=(timeout_text(str(error), seconds),),
                                code=QUERY_CHECK_TIMEOUT,
                            )
                        )
                        continue
                    streak.answered()
                    report.checks.append(check)
            streak.finish()
        return report


def _failed(rule: DetectionRule, tenant: str, error: str) -> RuleCheck:
    return RuleCheck(rule=str(rule.metadata.uuid), name=rule.name, tenant=tenant, errors=(error,))


def declare() -> GoogleSecopsValidator:
    """Factory for live query validation."""
    return GoogleSecopsValidator()
