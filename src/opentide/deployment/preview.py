"""Deploy preview helpers — compile API payloads without transmitting."""

from __future__ import annotations

from typing import Any, cast

import structlog

from opentide.models.rule import DetectionRule

logger = structlog.get_logger(__name__)


def _mock_sentinel_service() -> Any:
    from unittest.mock import MagicMock

    service = MagicMock()
    models = MagicMock()
    service.alert_rules.models.ScheduledAlertRule.return_value = MagicMock()
    service.alert_rules.models.AlertDetailsOverride.return_value = MagicMock()
    service.alert_rules.models.AlertPropertyMapping.return_value = MagicMock()
    service.alert_rules.models.EventGroupingSettings.return_value = MagicMock()
    service.alert_rules.models.IncidentConfiguration.return_value = MagicMock()
    service.alert_rules.models.GroupingConfiguration.return_value = MagicMock()
    service.alert_rules.models.EntityMapping.return_value = MagicMock()
    service.alert_rules.models.FieldMapping.return_value = MagicMock()
    service.alert_rules = MagicMock(models=models)
    return service


def _config_preview(platform: str, rule: DetectionRule) -> dict[str, Any]:
    config = getattr(rule.configurations, platform, None) if rule.configurations else None
    api_request: dict[str, Any] = {}
    if config is not None:
        api_request = config.model_dump(mode="json", by_alias=True)
    return {"uuid": rule.metadata.uuid, "name": rule.name, "api_request": api_request}


def _sentinel_compile_preview(rule: DetectionRule) -> dict[str, Any] | None:
    try:
        from opentide.platforms.sentinel.deployer import SentinelDeploy
    except Exception as exc:
        logger.debug("sentinel_preview_import_unavailable", error=str(exc))
        return None

    deployer = SentinelDeploy()
    service = _mock_sentinel_service()
    try:
        compiled = deployer.compile_deployment(
            service=service,
            data=rule,
            tenant="corpus-tenant",
        )
    except Exception as exc:
        logger.debug("sentinel_preview_compile_failed", error=str(exc))
        return None

    payload = compiled.as_dict() if hasattr(compiled, "as_dict") else dict(compiled)
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
