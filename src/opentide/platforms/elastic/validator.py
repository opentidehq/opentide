"""Live query validation engine for Elastic Security (RFC 0007 §6).

Each rule is previewed on its tenants as deploy would create it (the runner's
:meth:`~opentide.platforms.elastic.runner.ElasticQueryRunner.preview_rule`), so
the check covers the compiled rule (threshold, new terms, machine learning,
its schema), not the query alone. The RFC 0007 advisories and the
Elasticsearch checks are validation's own, on top of the preview.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, ClassVar

import structlog

from opentide.core.errors import Errors
from opentide.core.registry import DetectionPlatforms
from opentide.core.time import utc_now
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import RunStrategies
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, batch_tenant
from opentide.platforms.elastic import advisories
from opentide.platforms.elastic.advisories import warn_advisory
from opentide.platforms.elastic.attack import find_non_enterprise_techniques
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.compile import SEVERITY_TABLE, _alert_level, compile_rule
from opentide.platforms.elastic.durations import duration_seconds
from opentide.platforms.elastic.es_checks import (
    ElasticRuleCheckError,
    ElasticTenantError,
    run_elasticsearch_checks,
)
from opentide.platforms.elastic.query_text import (
    eql_is_sequence,
    eql_maxspan,
    esql_aggregates,
    esql_has_metadata_id,
)
from opentide.platforms.elastic.runner import ElasticQueryRunner
from opentide.platforms.live_validation import LiveQueryValidator, refusal_text
from opentide.platforms.transport import reaching_tenant
from opentide.query.check import LiveCheckReport, RuleCheck
from opentide.query.models import QueryRefused

logger = structlog.get_logger(__name__)

_RISK_BANDS: dict[str, tuple[int, int]] = {
    "low": (0, 21),
    "medium": (22, 47),
    "high": (48, 73),
    "critical": (74, 100),
}
_MAX_RECOMMENDED_LOOKBACK_SECONDS = 3600


def _emit_rule_advisories(
    rule: DetectionRule,
    block_dict: dict[str, Any],
    tenant: ConfigurationModels.Systems.Elastic.Tenant,
) -> list[str]:
    """Log RFC 0007 and Elastic Security configuration advisories; return them as warnings."""
    cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
    if not cfg:
        return []
    warnings: list[str] = []

    # 1. Look-back time advisories. The three conditions are independent: a rule can
    # trip more than one.
    interval_str = cfg.scheduling.interval if cfg.scheduling else "5m"
    lookback_str = cfg.scheduling.lookback if cfg.scheduling else "1m"
    interval_secs = duration_seconds(interval_str)
    lookback_secs = duration_seconds(lookback_str, allow_zero=True)

    if cfg.scheduling and lookback_secs == 0:
        warn_advisory(
            logger,
            advisories.LOOKBACK_ZERO,
            rule=rule.name,
            lookback=lookback_str,
            advice="scheduling.lookback is 0m; Elastic recommends at least 1m overlap",
        )
        warnings.append(advisories.LOOKBACK_ZERO)

    if lookback_secs > _MAX_RECOMMENDED_LOOKBACK_SECONDS:
        warn_advisory(
            logger,
            advisories.LOOKBACK_LONG,
            rule=rule.name,
            lookback=lookback_str,
            interval=interval_str,
            advice=(
                "scheduling.lookback exceeds 1h; in Elastic, lookback is additional "
                "overlap added to interval (from = now-(interval+lookback)), not the "
                "total query window"
            ),
        )
        warnings.append(advisories.LOOKBACK_LONG)

    if cfg.type == "threshold" and lookback_secs > interval_secs:
        warn_advisory(
            logger,
            advisories.THRESHOLD_LOOKBACK,
            rule=rule.name,
            lookback=lookback_str,
            interval=interval_str,
            advice=(
                "threshold rule has scheduling.lookback > scheduling.interval; "
                "threshold rules count across interval + lookback and do not "
                "deduplicate alerts across overlapping runs"
            ),
        )
        warnings.append(advisories.THRESHOLD_LOOKBACK)

    # 2. Non-aggregating ES|QL METADATA _id advisory
    if (
        cfg.type == "esql"
        and cfg.query
        and not esql_aggregates(cfg.query)
        and not esql_has_metadata_id(cfg.query)
    ):
        warn_advisory(
            logger,
            advisories.ESQL_METADATA_ID,
            rule=rule.name,
            advice=(
                "Non-aggregating ES|QL query lacks METADATA _id; alerts will not be deduplicated"
            ),
        )
        warnings.append(advisories.ESQL_METADATA_ID)

    # 3. Explicit risk.score outside RFC 0007 §3 severity band
    if cfg.risk is not None:
        explicit_score = cfg.risk if isinstance(cfg.risk, int) else cfg.risk.score
        if explicit_score is not None:
            raw_rule = rule.model_dump(by_alias=True, exclude_none=False)
            response_dict = raw_rule.get("response") or {}
            level = _alert_level(block_dict, response_dict)
            kibana_severity, _ = SEVERITY_TABLE[level]
            low, high = _RISK_BANDS[kibana_severity]
            if not (low <= explicit_score <= high):
                warn_advisory(
                    logger,
                    advisories.RISK_BAND,
                    rule=rule.name,
                    severity=kibana_severity,
                    risk_score=explicit_score,
                    expected_band=f"{low}-{high}",
                    advice=(
                        f"risk score {explicit_score} is outside the RFC 0007 band "
                        f"({low}-{high}) for severity '{kibana_severity}'"
                    ),
                )
                warnings.append(advisories.RISK_BAND)

    # 4. EQL sequence maxspan vs. scheduling window
    if cfg.type == "eql" and cfg.query and eql_is_sequence(cfg.query):
        maxspan = eql_maxspan(cfg.query)
        if maxspan:
            maxspan_str, maxspan_ms = maxspan
            window_ms = (interval_secs + lookback_secs) * 1000
            if maxspan_ms > window_ms:
                warn_advisory(
                    logger,
                    advisories.EQL_MAXSPAN_WINDOW,
                    rule=rule.name,
                    maxspan=maxspan_str,
                    interval=interval_str,
                    lookback=lookback_str,
                    advice=(
                        f"EQL sequence maxspan ({maxspan_str}) exceeds the total search "
                        f"window interval + lookback ({interval_str} + {lookback_str}); "
                        "sequences spanning the full maxspan cannot match"
                    ),
                )
                warnings.append(advisories.EQL_MAXSPAN_WINDOW)
            elif maxspan_ms > lookback_secs * 1000:
                warn_advisory(
                    logger,
                    advisories.EQL_MAXSPAN_LOOKBACK,
                    rule=rule.name,
                    maxspan=maxspan_str,
                    interval=interval_str,
                    lookback=lookback_str,
                    advice=(
                        f"EQL sequence maxspan ({maxspan_str}) exceeds scheduling.lookback "
                        f"({lookback_str}); sequences straddling two runs can be missed"
                    ),
                )
                warnings.append(advisories.EQL_MAXSPAN_LOOKBACK)

    # 5. Basic-licence tenant suppression omission
    if getattr(tenant.setup, "suppression", True) is False and cfg.suppression is not None:
        logger.warning(
            "suppression_omitted_basic_license",
            rule=rule.name,
            rule_id=_rule_uuid(rule),
            tenant=tenant.name,
            advice="Tenant setup.suppression is false; alert_suppression will be omitted",
        )
        warnings.append("suppression_omitted_basic_license")

    # 6. Non-Enterprise ATT&CK techniques skipped
    if find_non_enterprise_techniques(rule):
        warnings.append(advisories.TECHNIQUE_NOT_ENTERPRISE)
    return warnings


class ElasticValidator(LiveQueryValidator):
    """Validate detection rules against live Kibana and Elasticsearch instances."""

    platform: ClassVar[str] = "elastic"

    @property
    def elastic(self) -> ElasticQueryRunner:
        runner = self.runner
        if not isinstance(runner, ElasticQueryRunner):
            raise TypeError(f"expected the Elastic runner, got {type(runner).__qualname__}")
        return runner

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
    ) -> LiveCheckReport:
        deployment = TideDeployment(mdr_deployment, DetectionPlatforms.ELASTIC, strategies)
        report = LiveCheckReport(self.platform)
        for batch in deployment.rule_deployment:
            tenant = batch_tenant(batch, ConfigurationModels.Systems.Elastic.Tenant)
            client = self.elastic.elastic_client(tenant)
            with reaching_tenant("elastic", tenant.name, tenant.setup.url):
                for rule in batch.rules:
                    warnings: list[str] = []
                    try:
                        self._validate_rule(rule, client, tenant, warnings)
                    except ElasticTenantError as exc:
                        report.checks.append(_failed(rule, tenant, str(exc), warnings))
                        logger.critical(
                            "elastic_tenant_validation_failed",
                            rule=rule.name,
                            uuid=_rule_uuid(rule),
                            error=str(exc),
                        )
                        # The tenant refuses every rule alike: the rest are not sent.
                        break
                    except ElasticRuleCheckError as exc:
                        report.checks.append(_failed(rule, tenant, str(exc), warnings))
                        logger.critical(
                            "elastic_rule_validation_failed",
                            rule=rule.name,
                            uuid=_rule_uuid(rule),
                            error=str(exc),
                        )
                    else:
                        if getattr(rule.configurations, "elastic", None) is not None:
                            report.checks.append(
                                RuleCheck(
                                    rule=_rule_uuid(rule),
                                    name=rule.name,
                                    tenant=tenant.name,
                                    warnings=tuple(warnings),
                                )
                            )
        return report

    def _validate_rule(
        self,
        rule: DetectionRule,
        client: ElasticClient,
        tenant: ConfigurationModels.Systems.Elastic.Tenant,
        warnings: list[str],
    ) -> None:
        """Check *rule* on *tenant*, adding its warnings to *warnings*.

        Raises :class:`ElasticRuleCheckError` when the tenant refuses the rule
        and :class:`ElasticTenantError` when the tenant cannot check any rule.
        """
        cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
        if not cfg:
            return

        block_dict = cfg.model_dump(by_alias=True, exclude_none=False)
        warnings.extend(_emit_rule_advisories(rule, block_dict, tenant))

        for warning in run_elasticsearch_checks(
            client, block_dict, setup_index=list(tenant.setup.index or [])
        ):
            logger.warning("elasticsearch_check_warning", rule=rule.name, warning=warning)
            warnings.append(warning)

        payload = compile_rule(rule, tenant_config=tenant)
        try:
            res = self.elastic.preview_rule(tenant, payload, end=utc_now())
        except QueryRefused as exc:
            raise ElasticRuleCheckError(refusal_text(exc)) from exc
        except Errors.TenantConnectionError as exc:
            raise ElasticTenantError(str(exc)) from exc

        if res.get("isAborted") is True:
            logger.warning("preview_inconclusive_aborted", rule=rule.name)
            warnings.append("Kibana aborted the preview before it finished")

        logs = res.get("logs", [])
        error_msgs: list[str] = []
        for entry in logs:
            if not isinstance(entry, dict):
                continue
            for warning in entry.get("warnings", []):
                logger.warning("preview_log_warning", rule=rule.name, warning=str(warning))
                warnings.append(str(warning))
            for error in entry.get("errors", []):
                err_str = str(error)
                if "preview-index" in err_str or "preview.alerts" in err_str:
                    raise ElasticTenantError(
                        f"Tenant configuration error: missing preview-index privilege ({err_str})"
                    )
                error_msgs.append(err_str)

        if error_msgs:
            raise ElasticRuleCheckError(
                f"Preview validation failed for rule '{rule.name}': {'; '.join(error_msgs)}"
            )


def _failed(
    rule: DetectionRule,
    tenant: ConfigurationModels.Systems.Elastic.Tenant,
    error: str,
    warnings: list[str],
) -> RuleCheck:
    return RuleCheck(
        rule=_rule_uuid(rule),
        name=rule.name,
        tenant=tenant.name,
        errors=(error,),
        warnings=tuple(warnings),
    )


def _rule_uuid(rule: DetectionRule) -> str:
    metadata = getattr(rule, "metadata", None)
    return str(getattr(metadata, "uuid", "") or "")


def declare() -> ElasticValidator:
    """Factory for live query validation."""
    return ElasticValidator()
