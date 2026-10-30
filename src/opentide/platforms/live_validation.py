"""``validate query --live`` on the query runners: each rule checked where deploy sends it.

A platform's live check is its :class:`~opentide.query.runner.QueryRunner`'s
:meth:`~opentide.query.runner.QueryRunner.check`: a search for one row over the
last minute, or the platform's parse-only call where it has one (Splunk, Carbon
Black). The rule's queries are the ones deploy sends (:func:`rule_queries`), to
the tenants deploy sends them to (:class:`TideDeployment`). A refusal is that
rule's failure; the other rules are still checked. What only validation asks of
a query sits on top of the check's result (:meth:`LiveQueryValidator.inspect`).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

import structlog

from opentide.models.deployment_enums import RunStrategies
from opentide.models.rule import DetectionRule
from opentide.models.system_config import SystemConfig
from opentide.platforms.plugins import QueryValidator, resolve_rules
from opentide.query.check import CHECK_TIMEOUT, LiveCheckReport, RuleCheck, check_window
from opentide.query.models import LiveCheck, QueryRefused, QueryRequest, TimeWindow
from opentide.query.runner import QueryRunner

logger = structlog.get_logger(__name__)

#: The address a transport failure is reported against, for tenants configured without a URL.
_DEFAULT_HOSTS = {
    "sentinel": "https://api.loganalytics.io",
    "defender_for_endpoint": "https://graph.microsoft.com",
}


def refusal_text(refused: QueryRefused) -> str:
    """The refusal and the vendor's own message, as one line."""
    if refused.detail:
        return f"{refused.message}: {refused.detail}"
    return refused.message


class LiveQueryValidator(QueryValidator):
    """Checks rules' queries on their tenants through *platform*'s query runner."""

    platform: ClassVar[str]

    def __init__(self, runner: QueryRunner | None = None) -> None:
        self._runner = runner

    @property
    def runner(self) -> QueryRunner:
        if self._runner is None:
            from opentide.query.runner import load_runner

            self._runner = load_runner(self.platform)
        return self._runner

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
    ) -> LiveCheckReport:
        """Check each rule on each tenant a deploy with *strategies* sends it to.

        Lets an unreachable tenant (``TenantUnreachableError``), a credential
        the tenant refuses and a broken SDK through, for the caller to report
        once; a query the tenant refuses is a failed :class:`RuleCheck`.
        """
        from opentide.deployment import TideDeployment
        from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES, DetectionPlatforms
        from opentide.platforms.transport import reaching_tenant

        deployment = TideDeployment(
            deployment=resolve_rules(mdr_deployment),
            system=DetectionPlatforms[self.platform.upper()],
            strategies=strategies or DEPLOYABLE_STRATEGIES,
        )
        report = LiveCheckReport(self.platform)
        window = check_window()
        for batch in deployment.rule_deployment:
            tenant = batch.tenant
            with reaching_tenant(self.platform, tenant.name, self.host(tenant)):
                for rule in batch.rules:
                    report.checks.extend(self.check_rule(rule, tenant, window))
        return report

    def host(self, tenant: SystemConfig.Tenant) -> str:
        """The address an unreachable *tenant* is reported at."""
        setup = getattr(tenant, "setup", None)
        return str(getattr(setup, "url", "") or _DEFAULT_HOSTS.get(self.platform, ""))

    def check_rule(
        self, rule: DetectionRule, tenant: SystemConfig.Tenant, window: TimeWindow
    ) -> list[RuleCheck]:
        """*rule*'s queries on *tenant*: one check each."""
        from opentide.query.rules import RuleQueryError, rule_queries

        uuid = str(rule.metadata.uuid)
        if getattr(rule.platform_configs(), self.platform, None) is None:
            logger.info("rule_skipped", mdr_name=rule.name, reason=f"no {self.platform} block")
            return []
        try:
            queries = rule_queries(rule, self.platform)
        except RuleQueryError as exc:
            return [self._rejected(rule, tenant, None, str(exc))]
        checks: list[RuleCheck] = []
        for item in queries:
            request = QueryRequest(
                platform=self.platform,
                text=item.text_for(tenant.name),
                window=window,
                limit=1,
                language=item.language,
                index=item.index,
                data_view=item.data_view,
                label=item.label,
                timeout=CHECK_TIMEOUT,
            )
            logger.info("validating_query", mdr_name=rule.name, uuid=uuid, tenant=tenant.name)
            try:
                found = self.runner.check(request, tenant)
            except QueryRefused as exc:
                checks.append(self._rejected(rule, tenant, item.label, refusal_text(exc)))
                continue
            errors = tuple(self.inspect(rule, request, found))
            for error in errors:
                self._log_rejected(rule, tenant, error)
            for warning in found.warnings:
                logger.warning(
                    "query_validation_warning",
                    detail=f"{rule.name} ({uuid}) on {tenant.name}",
                    warning=warning,
                )
            if not errors:
                logger.info("valid_query", mdr_name=rule.name, tenant=tenant.name)
            checks.append(
                RuleCheck(
                    rule=uuid,
                    name=rule.name,
                    tenant=tenant.name,
                    label=item.label,
                    errors=errors,
                    warnings=found.warnings,
                )
            )
        return checks

    def inspect(
        self, rule: DetectionRule, request: QueryRequest, found: LiveCheck
    ) -> Sequence[str]:
        """Why validation fails a query the tenant accepted; none by default."""
        return ()

    def _rejected(
        self, rule: DetectionRule, tenant: SystemConfig.Tenant, label: str | None, error: str
    ) -> RuleCheck:
        self._log_rejected(rule, tenant, error)
        return RuleCheck(
            rule=str(rule.metadata.uuid),
            name=rule.name,
            tenant=tenant.name,
            label=label,
            errors=(error,),
        )

    def _log_rejected(self, rule: DetectionRule, tenant: SystemConfig.Tenant, error: str) -> None:
        logger.critical(
            "query_rejected",
            detail=f"{rule.name} ({rule.metadata.uuid}) on {self.platform} tenant {tenant.name}",
            reason=error,
        )
