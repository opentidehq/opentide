"""Live query validation engine for Elastic Security."""

from __future__ import annotations

from collections.abc import Sequence

import structlog

from opentide.core.registry import DetectionPlatforms
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.client import ElasticSecurityClient
from opentide.platforms.elastic_security.compile import compile_rule

logger = structlog.get_logger(__name__)


class ElasticSecurityValidator:
    """Validate detection rules against a live Kibana Detection Engine instance."""

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        deployment = TideDeployment(
            mdr_deployment, DetectionPlatforms.ELASTIC_SECURITY, deployment_plan
        )
        for batch in deployment.rule_deployment:
            tenant: ConfigurationModels.Systems.ElasticSecurity.Tenant = batch.tenant
            client = ElasticSecurityClient(
                kibana_url=tenant.setup.kibana_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=getattr(tenant.setup, "ssl", True),
                proxy=(
                    getattr(tenant.setup, "proxy", None)
                    if isinstance(getattr(tenant.setup, "proxy", None), str)
                    else None
                ),
            )
            for rule in batch.rules:
                if not getattr(rule.configurations, "elastic_security", None):
                    continue
                try:
                    payload = compile_rule(rule, tenant_config=tenant)
                    res = client.preview_rule(payload)
                    if isinstance(res, dict):
                        if res.get("isAborted") is True:
                            raise RuntimeError(
                                f"Preview for rule '{rule.name}' was aborted by Kibana"
                            )
                        # Check logs for errors
                        logs = res.get("logs", [])
                        error_msgs = []
                        for log_entry in logs:
                            if isinstance(log_entry, dict) and log_entry.get("errors"):
                                error_msgs.extend([str(e) for e in log_entry["errors"]])
                        if error_msgs:
                            raise RuntimeError(
                                f"Preview for rule '{rule.name}' reported errors: {'; '.join(error_msgs)}"
                            )
                except Exception as exc:
                    logger.warning(
                        "elastic_security_live_validation_failed",
                        rule=rule.name,
                        error=str(exc),
                    )
                    raise


def declare() -> ElasticSecurityValidator:
    """Factory for live query validation."""
    return ElasticSecurityValidator()
