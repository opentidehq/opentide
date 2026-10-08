"""Live query validation engine for Elastic Security (RFC 0007 §6)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime, timezone

import structlog

from opentide.core.registry import DetectionPlatforms
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.compile import compile_rule
from opentide.platforms.elastic.es_checks import run_elasticsearch_checks

logger = structlog.get_logger(__name__)


class ElasticValidator:
    """Validate detection rules against live Kibana and Elasticsearch instances."""

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        deployment = TideDeployment(
            mdr_deployment, DetectionPlatforms.ELASTIC, deployment_plan
        )
        for batch in deployment.rule_deployment:
            tenant: ConfigurationModels.Systems.Elastic.Tenant = batch.tenant
            client = ElasticClient(
                url=tenant.setup.url,
                elasticsearch_url=tenant.setup.elasticsearch_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=getattr(tenant.setup, "ssl", True),
            )
            for rule in batch.rules:
                cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
                if not cfg:
                    continue

                # RFC Warnings
                if cfg.scheduling and cfg.scheduling.lookback == "0m":
                    logger.warning(
                        "elastic_lookback_zero_warning",
                        rule=rule.name,
                        advice="scheduling.lookback is 0m; Elastic recommends at least 1m overlap",
                    )
                if cfg.type == "esql" and cfg.query:
                    if not re.search(r"(?i)\bSTATS\b", cfg.query) and "METADATA _id" not in cfg.query:
                        logger.warning(
                            "elastic_esql_metadata_id_warning",
                            rule=rule.name,
                            advice="Non-aggregating ES|QL query lacks METADATA _id; alerts will not be deduplicated",
                        )

                # Mandatory Elasticsearch pre-flight checks
                block_dict = cfg.model_dump(by_alias=True, exclude_none=False)
                run_elasticsearch_checks(client, block_dict, setup_index=list(tenant.setup.index or []))

                # Live preview validation
                payload = compile_rule(rule, tenant_config=tenant)
                now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                resp = client.preview_rule(payload, invocation_count=1, timeframe_end=now_utc)

                if resp.status_code == 400:
                    raise ValueError(f"Rule schema error on preview: {resp.text}")
                if resp.status_code in (401, 403):
                    raise RuntimeError(f"Tenant authentication/authorization failed: HTTP {resp.status_code}")

                resp.raise_for_status()
                res = resp.json()

                if res.get("isAborted") is True:
                    logger.warning("preview_inconclusive_aborted", rule=rule.name)

                logs = res.get("logs", [])
                error_msgs: list[str] = []
                for entry in logs:
                    if not isinstance(entry, dict):
                        continue
                    for warning in entry.get("warnings", []):
                        logger.warning("preview_log_warning", rule=rule.name, warning=str(warning))
                    for error in entry.get("errors", []):
                        err_str = str(error)
                        if "preview-index" in err_str or "preview.alerts" in err_str:
                            raise RuntimeError(
                                f"Tenant configuration error: missing preview-index privilege ({err_str})"
                            )
                        error_msgs.append(err_str)

                if error_msgs:
                    raise ValueError(
                        f"Preview validation failed for rule '{rule.name}': {'; '.join(error_msgs)}"
                    )


def declare() -> ElasticValidator:
    """Factory for live query validation."""
    return ElasticValidator()
