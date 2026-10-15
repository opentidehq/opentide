"""Deploy preview helpers — compile API payloads without transmitting."""

from __future__ import annotations

import os
from typing import Any, cast

import structlog

from opentide.models.rule import DetectionRule

logger = structlog.get_logger(__name__)


def _config_preview(platform: str, rule: DetectionRule) -> dict[str, Any]:
    config = getattr(rule.configurations, platform, None) if rule.configurations else None
    api_request: dict[str, Any] = {}
    if config is not None:
        api_request = config.model_dump(mode="json", by_alias=True)
    return {"uuid": rule.metadata.uuid, "name": rule.name, "api_request": api_request}


# Exclusions scoped to a tenant name are left out of the preview; the payload
# shows the rule as any tenant without a tenant-specific exclusion receives it.
_PREVIEW_TENANT = "corpus-tenant"


def _compile_failure(rule: DetectionRule, exc: Exception) -> dict[str, Any]:
    """Record a rule that would fail to deploy, and fail the dry-run with it."""
    error = f"{type(exc).__name__}: {exc}" if str(exc).strip() else type(exc).__name__
    logger.error(
        "sentinel_preview_compile_failed",
        detail=f"{rule.name} ({rule.metadata.uuid}) would fail to deploy: {error}",
    )
    # Read by deployment_outcome(): the dry-run reports failed and exits 1.
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    return {
        "uuid": rule.metadata.uuid,
        "name": rule.name,
        "status": "failed",
        "error": error,
        "api_request": None,
    }


def _sentinel_compile_preview(rule: DetectionRule) -> dict[str, Any] | None:
    """Compile and serialise the ARM request body, offline, with the real SDK models.

    Returns ``None`` only when the ``sentinel`` extra is not installed, so the
    caller falls back to the configuration block. Any compilation or
    serialisation error is a failure for the rule, never a silent fallback.
    """
    from opentide.platforms.sentinel.client import alert_rule_request_body, securityinsight_models

    try:
        securityinsight_models()
    except ImportError as exc:
        logger.debug("sentinel_preview_sdk_unavailable", error=str(exc))
        return None
    from opentide.platforms.sentinel.deployer import SentinelDeploy

    try:
        compiled = SentinelDeploy().compile_deployment(
            service=None, data=rule, tenant=_PREVIEW_TENANT
        )
        payload = alert_rule_request_body(compiled)
    except Exception as exc:
        return _compile_failure(rule, exc)
    return {"uuid": rule.metadata.uuid, "name": rule.name, "api_request": payload}


def preview_rule_deployment(platform: str, rule: DetectionRule) -> dict[str, Any]:
    """Return a serialisable preview of the API payload for one rule on a platform."""
    if platform == "sentinel":
        compiled = _sentinel_compile_preview(rule)
        if compiled is not None:
            return compiled
    return _config_preview(platform, rule)


def preview_platform_deployment(
    platform: str, uuids: list[str], *, rules_by_uuid: dict[str, DetectionRule] | None = None
) -> list[dict[str, Any]]:
    """Preview deployment payloads for a list of rule UUIDs on one platform."""
    from opentide.core.registry import OpenTide

    OpenTide.initialise()
    previews: list[dict[str, Any]] = []
    for uuid in uuids:
        if rules_by_uuid is not None:
            rule = rules_by_uuid.get(uuid)
        else:
            rule = OpenTide.Rules[uuid]
        if rule is None:
            continue
        if isinstance(rule, DetectionRule):
            previews.append(preview_rule_deployment(platform, rule))
        else:
            previews.append(cast(dict[str, Any], rule))
    return previews
