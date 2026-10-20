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


def _sentinel_compile_preview(rule: DetectionRule) -> dict[str, Any]:
    """Compile the ARM request body offline, exactly as a deploy would send it.

    Any compilation error is a failure for the rule, never a silent fallback.
    """
    from opentide.platforms.sentinel.deployer import SentinelDeploy

    try:
        payload = SentinelDeploy().compile_deployment(
            service=None, data=rule, tenant=_PREVIEW_TENANT
        )
    except Exception as exc:
        return _compile_failure(rule, exc)
    return {"uuid": rule.metadata.uuid, "name": rule.name, "api_request": payload}


def _elastic_compile_preview(rule: DetectionRule) -> dict[str, Any] | None:
    try:
        from opentide.platforms.elastic.compile import compile_rule
    except Exception as exc:
        logger.debug("elastic_preview_import_unavailable", error=str(exc))
        return None
    try:
        payload = compile_rule(rule)
    except Exception as exc:
        logger.debug("elastic_preview_compile_failed", error=str(exc))
        return None
    return {"uuid": rule.metadata.uuid, "name": rule.name, "api_request": payload}


def preview_rule_deployment(platform: str, rule: DetectionRule) -> dict[str, Any]:
    """Return a serialisable preview of the API payload for one rule on a platform."""
    if platform == "sentinel":
        return _sentinel_compile_preview(rule)
    if platform == "elastic":
        compiled = _elastic_compile_preview(rule)
        if compiled is not None:
            return compiled
    return _config_preview(platform, rule)


def preview_platform_deployment(
    platform: str, uuids: list[str], *, rules_by_uuid: dict[str, DetectionRule] | None = None
) -> list[dict[str, Any]]:
    """Preview deployment payloads for a list of rule UUIDs on one platform."""
    from opentide.core.registry import Opentide

    Opentide.initialise()
    previews: list[dict[str, Any]] = []
    for uuid in uuids:
        if rules_by_uuid is not None:
            rule = rules_by_uuid.get(uuid)
        else:
            rule = Opentide.Rules[uuid]
        if rule is None:
            continue
        if isinstance(rule, DetectionRule):
            previews.append(preview_rule_deployment(platform, rule))
        else:
            previews.append(cast(dict[str, Any], rule))
    return previews
