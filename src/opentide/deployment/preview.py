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


def compile_diagnostic(exc: Exception, platform: str = "Sentinel") -> tuple[str, str, str | None]:
    """``(code, message, help)`` for a rule that does not compile, in the reader's words.

    A compiler error that knows its cause carries ``code``, ``reason`` and
    ``hint``. A Python error (an ``AttributeError`` on an empty block, say) is
    described, never printed as ``ClassName: text``. *platform* is the
    platform's display name.
    """
    code = getattr(exc, "code", None)
    reason = getattr(exc, "reason", None)
    if isinstance(code, str) and isinstance(reason, str):
        hint = getattr(exc, "hint", None)
        return code, reason, hint if isinstance(hint, str) else None
    if isinstance(exc, AttributeError) and exc.name and getattr(exc, "obj", object()) is None:
        return (
            "compile_empty_block",
            f"a block this rule needs is empty, so {platform} cannot read `{exc.name}`",
            None,
        )
    from opentide.core.errors import Errors

    text = str(exc).strip()
    if isinstance(exc, Errors.TideRuleDataModelErrors) and text:
        return "compile_invalid_rule", text, None
    return (
        "compile_failed",
        f"{platform} cannot compile this rule: {text or 'no detail given'}",
        None,
    )


def _compile_failure(rule: DetectionRule, exc: Exception) -> dict[str, Any]:
    """Record a rule that would fail to deploy, and fail the dry-run with it.

    The deploy result reports it once, as a diagnostic above the plan tally;
    the Python error stays in the ``--debug`` log.
    """
    code, message, hint = compile_diagnostic(exc)
    logger.debug(
        "sentinel_preview_compile_failed",
        uuid=str(rule.metadata.uuid),
        code=code,
        error=f"{type(exc).__name__}: {exc}",
    )
    # Read by deployment_outcome(): the dry-run reports failed and exits 1.
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"
    source = getattr(rule, "file", None)
    return {
        "uuid": rule.metadata.uuid,
        "name": rule.name,
        "status": "failed",
        "code": code,
        "error": message,
        "help": hint,
        "file": str(source) if source else None,
        "api_request": None,
    }


#: Platforms whose request body opentide builds from the rule alone, with no
#: tenant: ``validate`` compiles each rule they would deploy, so a rule that
#: validates compiles.
OFFLINE_COMPILERS = frozenset({"sentinel", "elastic"})


def compile_offline(platform: str, rule: DetectionRule) -> dict[str, Any]:
    """The request body a deploy would send for *rule* on *platform*; raises when it cannot.

    *platform* is one of :data:`OFFLINE_COMPILERS`.
    """
    if platform == "sentinel":
        from opentide.platforms.sentinel.deployer import SentinelDeploy

        return SentinelDeploy().compile_deployment(service=None, data=rule, tenant=_PREVIEW_TENANT)
    if platform == "elastic":
        from opentide.platforms.elastic.compile import compile_rule

        return compile_rule(rule)
    raise ValueError(f"{platform} has no offline compiler")


def _sentinel_compile_preview(rule: DetectionRule) -> dict[str, Any]:
    """Compile the ARM request body offline, exactly as a deploy would send it.

    Any compilation error is a failure for the rule, never a silent fallback.
    """
    try:
        payload = compile_offline("sentinel", rule)
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
        rule = rules_by_uuid.get(uuid) if rules_by_uuid is not None else Opentide.Rules[uuid]
        if rule is None:
            continue
        if isinstance(rule, DetectionRule):
            previews.append(preview_rule_deployment(platform, rule))
        else:
            previews.append(cast(dict[str, Any], rule))
    return previews
