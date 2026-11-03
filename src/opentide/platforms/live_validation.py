"""``validate query --live`` on the query runners: each rule checked where deploy sends it.

A platform's live check is its :class:`~opentide.query.runner.QueryRunner`'s
:meth:`~opentide.query.runner.QueryRunner.check`: a search for one row over the
last minute, or the platform's parse-only call where it has one (Splunk, Carbon
Black). The rule's queries are the ones deploy sends (:func:`rule_queries`), to
the tenants deploy sends them to (:class:`TideDeployment`). A refusal is that
rule's failure; the other rules are still checked. So is a query that gets no
answer within the check timeout (``query_check_timeout``): only
:data:`~opentide.query.check.UNREACHABLE_AFTER_TIMEOUTS` of them in a row on one
tenant report it unreachable. What only validation asks of a query sits on top
of the check's result (:meth:`LiveQueryValidator.inspect`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

import structlog

from opentide.models.deployment_enums import RunStrategies
from opentide.models.rule import DetectionRule
from opentide.models.system_config import SystemConfig
from opentide.platforms.plugins import QueryValidator, resolve_rules
from opentide.query.check import (
    CHECK_TIMEOUT_ENV,
    QUERY_CHECK_TIMEOUT,
    UNREACHABLE_AFTER_TIMEOUTS,
    LiveCheckReport,
    RuleCheck,
    check_timeout,
    check_window,
)
from opentide.query.models import LiveCheck, QueryRefused, QueryRequest, QueryTimedOut, TimeWindow
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


def timeout_text(reason: str, timeout: float) -> str:
    """A query check that got no answer within *timeout* seconds, and how to wait longer."""
    return (
        f"no answer within the {timeout:g}s check timeout ({reason}). Raise it with "
        f"--check-timeout or {CHECK_TIMEOUT_ENV}, or make the query cheaper"
    )


@dataclass
class TimeoutStreak:
    """The queries in a row that got no answer on one tenant.

    :meth:`timed_out` raises :class:`~opentide.platforms.transport.TenantUnreachableError`
    at the :data:`~opentide.query.check.UNREACHABLE_AFTER_TIMEOUTS`-th: a tenant
    that answers no query is not waited on for every rule.
    """

    platform: str
    tenant: str
    host: str
    timeout: float
    count: int = 0

    def answered(self) -> None:
        self.count = 0

    def timed_out(self, error: BaseException) -> None:
        from opentide.platforms.transport import TenantUnreachableError

        self.count += 1
        if self.count >= UNREACHABLE_AFTER_TIMEOUTS:
            raise TenantUnreachableError(
                self.platform,
                self.tenant,
                self.host,
                error,
                reason=(
                    f"{self.count} queries in a row got no answer within the {self.timeout:g}s "
                    f"check timeout (the last: {error}); a tenant is reported unreachable after "
                    f"{UNREACHABLE_AFTER_TIMEOUTS} in a row"
                ),
                timeouts=self.count,
            )


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
        *,
        timeout: float | None = None,
    ) -> LiveCheckReport:
        """Check each rule on each tenant a deploy with *strategies* sends it to.

        Each query may take *timeout* seconds (default: :func:`check_timeout`).
        Lets an unreachable tenant (``TenantUnreachableError``), a credential
        the tenant refuses and a broken SDK through, for the caller to report
        once; a query the tenant refuses, or does not answer in time, is a
        failed :class:`RuleCheck`.
        """
        from opentide.deployment import TideDeployment
        from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES, DetectionPlatforms
        from opentide.platforms.transport import reaching_tenant

        seconds = check_timeout(timeout)
        deployment = TideDeployment(
            deployment=resolve_rules(mdr_deployment),
            system=DetectionPlatforms[self.platform.upper()],
            strategies=strategies or DEPLOYABLE_STRATEGIES,
        )
        report = LiveCheckReport(self.platform, timeout=seconds)
        window = check_window()
        for batch in deployment.rule_deployment:
            tenant = batch.tenant
            host = self.host(tenant)
            streak = TimeoutStreak(self.platform, tenant.name, host, seconds)
            with reaching_tenant(self.platform, tenant.name, host):
                for rule in batch.rules:
                    report.checks.extend(self.check_rule(rule, tenant, window, streak=streak))
        return report

    def host(self, tenant: SystemConfig.Tenant) -> str:
        """The address an unreachable *tenant* is reported at."""
        setup = getattr(tenant, "setup", None)
        return str(getattr(setup, "url", "") or _DEFAULT_HOSTS.get(self.platform, ""))

    def check_rule(
        self,
        rule: DetectionRule,
        tenant: SystemConfig.Tenant,
        window: TimeWindow,
        *,
        streak: TimeoutStreak | None = None,
    ) -> list[RuleCheck]:
        """*rule*'s queries on *tenant*: one check each.

        *streak* counts the queries in a row on *tenant* that got no answer;
        without one, the call starts its own, with :func:`check_timeout`.
        """
        from opentide.platforms.transport import read_timeout
        from opentide.query.rules import RuleQueryError, rule_queries

        if streak is None:
            streak = TimeoutStreak(self.platform, tenant.name, self.host(tenant), check_timeout())
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
                timeout=streak.timeout,
            )
            logger.info("validating_query", mdr_name=rule.name, uuid=uuid, tenant=tenant.name)
            try:
                found = self.runner.check(request, tenant)
            except QueryTimedOut as exc:
                # The tenant answered: the search was still running at the deadline.
                # Its detail advises `opentide query --timeout`; timed_out names ours.
                streak.answered()
                checks.append(self.timed_out(rule, tenant, item.label, exc.message, streak.timeout))
                continue
            except QueryRefused as exc:
                streak.answered()
                checks.append(self._rejected(rule, tenant, item.label, refusal_text(exc)))
                continue
            except Exception as exc:
                error = read_timeout(exc)
                if error is None:
                    raise
                streak.timed_out(error)
                checks.append(self.timed_out(rule, tenant, item.label, str(error), streak.timeout))
                continue
            streak.answered()
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

    def timed_out(
        self,
        rule: DetectionRule,
        tenant: SystemConfig.Tenant,
        label: str | None,
        reason: str,
        timeout: float,
        warnings: Sequence[str] = (),
    ) -> RuleCheck:
        """*rule*'s failed check: its query got no answer within *timeout* seconds."""
        error = timeout_text(reason, timeout)
        logger.critical(
            "query_check_timed_out",
            detail=f"{rule.name} ({rule.metadata.uuid}) on {self.platform} tenant {tenant.name}",
            reason=error,
        )
        return RuleCheck(
            rule=str(rule.metadata.uuid),
            name=rule.name,
            tenant=tenant.name,
            label=label,
            errors=(error,),
            warnings=tuple(warnings),
            code=QUERY_CHECK_TIMEOUT,
        )

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
