"""Live query validation engine for Elastic Security (RFC 0007 §6)."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

import structlog

from opentide.core.registry import DetectionPlatforms
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import RunStrategies
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, batch_tenant
from opentide.platforms.elastic.attack import find_non_enterprise_techniques
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.compile import SEVERITY_TABLE, _alert_level, compile_rule
from opentide.platforms.elastic.durations import duration_seconds
from opentide.platforms.elastic.es_checks import (
    ElasticRuleCheckError,
    ElasticTenantError,
    run_elasticsearch_checks,
)
from opentide.platforms.plugins import QueryValidator
from opentide.platforms.transport import reaching_tenant, tenant_tls_verify

logger = structlog.get_logger(__name__)

_METADATA_ID = re.compile(r"(?i)\bMETADATA\b[^|]*\b_id\b")
_STATS = re.compile(r"(?i)\bSTATS\b")
_EQL_SEQUENCE = re.compile(r"(?i)\bsequence\b")
_EQL_MAXSPAN = re.compile(r"(?i)\bmaxspan\s*=\s*(\d+[smhd])")

_RISK_BANDS: dict[str, tuple[int, int]] = {
    "low": (0, 21),
    "medium": (22, 47),
    "high": (48, 73),
    "critical": (74, 100),
}
_MAX_RECOMMENDED_LOOKBACK_SECONDS = 3600


def _flag_error() -> None:
    os.environ["VALIDATION_ERROR_RAISED"] = "1"


def _flag_warning() -> None:
    os.environ["VALIDATION_WARNING_RAISED"] = "1"


def _emit_rule_advisories(
    rule: DetectionRule,
    block_dict: dict[str, Any],
    tenant: ConfigurationModels.Systems.Elastic.Tenant,
) -> None:
    """Emit RFC 0007 and Elastic Security configuration advisories as warnings."""
    cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
    if not cfg:
        return

    # 1. Look-back time advisories (0s/0m and >1h or threshold > interval)
    interval_str = cfg.scheduling.interval if cfg.scheduling else "5m"
    lookback_str = cfg.scheduling.lookback if cfg.scheduling else "1m"
    interval_secs = duration_seconds(interval_str)
    lookback_secs = duration_seconds(lookback_str, allow_zero=True)

    if cfg.scheduling and lookback_secs == 0:
        logger.warning(
            "elastic_lookback_zero_warning",
            rule=rule.name,
            lookback=lookback_str,
            advice="scheduling.lookback is 0m; Elastic recommends at least 1m overlap",
        )
        _flag_warning()
    elif lookback_secs > _MAX_RECOMMENDED_LOOKBACK_SECONDS:
        logger.warning(
            "elastic_lookback_long_warning",
            rule=rule.name,
            lookback=lookback_str,
            interval=interval_str,
            advice=(
                "scheduling.lookback exceeds 1h; in Elastic, lookback is additional "
                "overlap added to interval (from = now-(interval+lookback)), not the "
                "total query window"
            ),
        )
        _flag_warning()
    elif cfg.type == "threshold" and lookback_secs > interval_secs:
        logger.warning(
            "elastic_lookback_long_warning",
            rule=rule.name,
            lookback=lookback_str,
            interval=interval_str,
            advice=(
                "threshold rule has scheduling.lookback > scheduling.interval; "
                "threshold rules count across interval + lookback and do not "
                "deduplicate alerts across overlapping runs"
            ),
        )
        _flag_warning()

    # 2. Non-aggregating ES|QL METADATA _id advisory
    if (
        cfg.type == "esql"
        and cfg.query
        and not _STATS.search(cfg.query)
        and not _METADATA_ID.search(cfg.query)
    ):
        logger.warning(
            "elastic_esql_metadata_id_warning",
            rule=rule.name,
            advice=(
                "Non-aggregating ES|QL query lacks METADATA _id; alerts will not be deduplicated"
            ),
        )
        _flag_warning()

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
                logger.warning(
                    "elastic_risk_score_band_warning",
                    rule=rule.name,
                    severity=kibana_severity,
                    risk_score=explicit_score,
                    expected_band=f"{low}-{high}",
                    advice=(
                        f"risk score {explicit_score} is outside the RFC 0007 band "
                        f"({low}-{high}) for severity '{kibana_severity}'"
                    ),
                )
                _flag_warning()

    # 4. EQL sequence maxspan vs. scheduling window
    if cfg.type == "eql" and cfg.query and _EQL_SEQUENCE.search(cfg.query):
        maxspan_match = _EQL_MAXSPAN.search(cfg.query)
        if maxspan_match:
            maxspan_str = maxspan_match.group(1)
            try:
                maxspan_secs = duration_seconds(maxspan_str)
            except ValueError:
                maxspan_secs = 0
            window_secs = interval_secs + lookback_secs
            if maxspan_secs > window_secs:
                logger.warning(
                    "elastic_eql_maxspan_window_warning",
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
                _flag_warning()
            elif maxspan_secs > lookback_secs:
                logger.warning(
                    "elastic_eql_maxspan_window_warning",
                    rule=rule.name,
                    maxspan=maxspan_str,
                    interval=interval_str,
                    lookback=lookback_str,
                    advice=(
                        f"EQL sequence maxspan ({maxspan_str}) exceeds scheduling.lookback "
                        f"({lookback_str}); sequences straddling two runs can be missed"
                    ),
                )
                _flag_warning()

    # 5. Basic-licence tenant suppression omission
    if getattr(tenant.setup, "suppression", True) is False and cfg.suppression is not None:
        logger.warning(
            "suppression_omitted_basic_license",
            rule=rule.name,
            rule_id=_rule_uuid(rule),
            tenant=tenant.name,
            advice="Tenant setup.suppression is false; alert_suppression will be omitted",
        )
        _flag_warning()

    # 6. Non-Enterprise ATT&CK techniques skipped
    if find_non_enterprise_techniques(rule):
        _flag_warning()


class ElasticValidator(QueryValidator):
    """Validate detection rules against live Kibana and Elasticsearch instances."""

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
    ) -> None:
        deployment = TideDeployment(mdr_deployment, DetectionPlatforms.ELASTIC, strategies)
        for batch in deployment.rule_deployment:
            tenant = batch_tenant(batch, ConfigurationModels.Systems.Elastic.Tenant)
            client = ElasticClient(
                url=tenant.setup.url,
                elasticsearch_url=tenant.setup.elasticsearch_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=tenant_tls_verify(
                    getattr(tenant.setup, "ssl", True), platform="elastic", tenant=tenant.name
                ),
            )
            with reaching_tenant("elastic", tenant.name, tenant.setup.url):
                for rule in batch.rules:
                    try:
                        self._validate_rule(rule, client, tenant)
                    except ElasticTenantError as exc:
                        logger.critical(
                            "elastic_tenant_validation_failed",
                            rule=rule.name,
                            uuid=_rule_uuid(rule),
                            error=str(exc),
                        )
                        _flag_error()
                        break
                    except ElasticRuleCheckError as exc:
                        logger.critical(
                            "elastic_rule_validation_failed",
                            rule=rule.name,
                            uuid=_rule_uuid(rule),
                            error=str(exc),
                        )
                        _flag_error()

    def _validate_rule(
        self,
        rule: DetectionRule,
        client: ElasticClient,
        tenant: ConfigurationModels.Systems.Elastic.Tenant,
    ) -> None:
        cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
        if not cfg:
            return

        block_dict = cfg.model_dump(by_alias=True, exclude_none=False)
        _emit_rule_advisories(rule, block_dict, tenant)

        for warning in run_elasticsearch_checks(
            client, block_dict, setup_index=list(tenant.setup.index or [])
        ):
            logger.warning("elasticsearch_check_warning", rule=rule.name, warning=warning)
            _flag_warning()

        payload = compile_rule(rule, tenant_config=tenant)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        resp = client.preview_rule(payload, invocation_count=1, timeframe_end=now_utc)

        if resp.status_code == 400:
            raise ElasticRuleCheckError(f"Rule schema error on preview: {resp.text}")
        if resp.status_code in (401, 403):
            raise ElasticTenantError(
                f"Tenant authentication/authorization failed: HTTP {resp.status_code}"
            )

        if resp.status_code != 200:
            # 429 and 5xx were already retried by the client (RFC 0007 §5). Anything
            # left fails this rule only; it must not abort the remaining rules.
            raise ElasticRuleCheckError(f"Preview failed (HTTP {resp.status_code}): {resp.text}")
        res = resp.json()

        if res.get("isAborted") is True:
            logger.warning("preview_inconclusive_aborted", rule=rule.name)
            _flag_warning()

        logs = res.get("logs", [])
        error_msgs: list[str] = []
        for entry in logs:
            if not isinstance(entry, dict):
                continue
            for warning in entry.get("warnings", []):
                logger.warning("preview_log_warning", rule=rule.name, warning=str(warning))
                _flag_warning()
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


def _rule_uuid(rule: DetectionRule) -> str:
    metadata = getattr(rule, "metadata", None)
    return str(getattr(metadata, "uuid", "") or "")


def declare() -> ElasticValidator:
    """Factory for live query validation."""
    return ElasticValidator()
