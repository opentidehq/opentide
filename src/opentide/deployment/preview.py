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


#: Each offline compiler's platform, as a diagnostic names it.
PLATFORM_LABELS: dict[str, str] = {
    "sentinel": "Sentinel",
    "elastic": "Elastic",
    "sysdig": "Sysdig",
    "bitdefender": "Bitdefender GravityZone",
    "google_secops": "Google SecOps",
}


def compile_diagnostic(
    exc: Exception, platform: str = "the platform"
) -> tuple[str, str, str | None]:
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


def _compile_failure(rule: DetectionRule, exc: Exception, platform: str) -> dict[str, Any]:
    """Record a rule that would fail to deploy, and fail the dry-run with it.

    The deploy result reports it once, as a diagnostic above the plan tally;
    the Python error stays in the ``--debug`` log.
    """
    code, message, hint = compile_diagnostic(exc, PLATFORM_LABELS.get(platform, platform))
    logger.debug(
        "preview_compile_failed",
        platform=platform,
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
OFFLINE_COMPILERS = frozenset({"sentinel", "elastic", "sysdig", "bitdefender", "google_secops"})


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
    if platform == "sysdig":
        from opentide.platforms.sysdig.compile import api_body
        from opentide.platforms.sysdig.deployer import SysdigDeploy

        return api_body(SysdigDeploy().compile_deployment(rule))
    if platform == "bitdefender":
        from opentide.platforms.bitdefender.compile import create_params, request_body
        from opentide.platforms.bitdefender.deployer import BitdefenderDeploy

        compiled = BitdefenderDeploy().compile_deployment(rule)
        return request_body("createCustomRule", create_params(compiled))
    if platform == "google_secops":
        from opentide.platforms.google_secops.compile import assemble

        # The rules.create body; a tenant's data_access_scope adds its scope.
        return {"text": assemble(rule).text}
    raise ValueError(f"{platform} has no offline compiler")


def _sentinel_compile_preview(rule: DetectionRule) -> dict[str, Any]:
    """Compile the ARM request body offline, exactly as a deploy would send it.

    Any compilation error is a failure for the rule, never a silent fallback.
    """
    try:
        payload = compile_offline("sentinel", rule)
    except Exception as exc:
        return _compile_failure(rule, exc, "sentinel")
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


def _sysdig_compile_preview(rule: DetectionRule) -> dict[str, Any]:
    """The Sysdig Secure ``/api/secure/rules`` body the deploy would send."""
    try:
        from opentide.platforms.sysdig.compile import api_body
        from opentide.platforms.sysdig.deployer import SysdigDeploy

        compiled = SysdigDeploy().compile_deployment(rule)
    except Exception as exc:
        return _compile_failure(rule, exc, "sysdig")
    return {"uuid": rule.metadata.uuid, "name": rule.name, "api_request": api_body(compiled)}


def _bitdefender_tenant(name: str | None) -> Any | None:
    """The GravityZone tenant named *name*, or ``None``."""
    if name is None:
        return None
    try:
        from opentide.core.registry import Opentide

        tenants = Opentide.Configurations.Systems.Bitdefender.tenants or []
    except Exception as exc:
        logger.debug("bitdefender_preview_no_tenant", error=str(exc))
        return None
    return next((tenant for tenant in tenants if tenant.name == name), None)


def _bitdefender_compile_preview(rule: DetectionRule, tenant_names: list[str]) -> dict[str, Any]:
    """The GravityZone ``createCustomRule`` request the deploy would send.

    *tenant_names* are the tenants this run sends the rule to. The rule is
    compiled for each, as a deploy would: one that cannot resolve its targets
    fails the dry run, naming that tenant. The request shown is the first
    tenant's. With no tenant, the request leaves targets, tenant tags and
    ``companyId`` out and ``unresolved`` lists the block's target aliases, never
    presented as GravityZone ids.
    """
    from opentide.platforms.bitdefender.compile import (
        create_params,
        request_body,
        unresolved_targets,
    )
    from opentide.platforms.bitdefender.deployer import BitdefenderDeploy

    tenants = [tenant for name in tenant_names if (tenant := _bitdefender_tenant(name))]
    compiled = []
    try:
        for tenant in tenants or [None]:
            compiled.append(BitdefenderDeploy().compile_deployment(rule, tenant))
    except Exception as exc:
        return _compile_failure(rule, exc, "bitdefender")
    preview: dict[str, Any] = {
        "uuid": rule.metadata.uuid,
        "name": rule.name,
        "api_request": request_body("createCustomRule", create_params(compiled[0])),
    }
    if tenants:
        preview["tenant"] = tenants[0].name
    else:
        preview["unresolved"] = {
            "reason": "this run deploys the rule to no bitdefender tenant: targets, tenant "
            "tags and companyId are resolved against a tenant at deploy",
            "targets": unresolved_targets(rule),
        }
    return preview


def _google_secops_compile_preview(rule: DetectionRule) -> dict[str, Any]:
    """The Chronicle ``rules.create`` body: the YARA-L text deploy verifies, then creates."""
    try:
        payload = compile_offline("google_secops", rule)
    except Exception as exc:
        return _compile_failure(rule, exc, "google_secops")
    return {"uuid": rule.metadata.uuid, "name": rule.name, "api_request": payload}


def preview_rule_deployment(
    platform: str, rule: DetectionRule, tenants: list[str] | None = None
) -> dict[str, Any]:
    """A serialisable preview of the API payload for one rule on a platform.

    *tenants* are the tenants the run sends the rule to, for platforms whose
    request depends on the tenant (Bitdefender).
    """
    if platform == "sentinel":
        return _sentinel_compile_preview(rule)
    if platform == "sysdig":
        return _sysdig_compile_preview(rule)
    if platform == "bitdefender":
        return _bitdefender_compile_preview(rule, list(tenants or []))
    if platform == "google_secops":
        return _google_secops_compile_preview(rule)
    if platform == "elastic":
        compiled = _elastic_compile_preview(rule)
        if compiled is not None:
            return compiled
    return _config_preview(platform, rule)


def preview_platform_deployment(
    platform: str,
    uuids: list[str],
    *,
    rules_by_uuid: dict[str, DetectionRule] | None = None,
    tenant_targets: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Preview deployment payloads for a list of rule UUIDs on one platform.

    *tenant_targets* maps each tenant the run reaches to the rules it sends
    there, after the run's strategies: a rule is resolved against every one of
    them that receives it.
    """
    from opentide.core.registry import Opentide

    Opentide.initialise()
    previews: list[dict[str, Any]] = []
    for uuid in uuids:
        rule = rules_by_uuid.get(uuid) if rules_by_uuid is not None else Opentide.Rules[uuid]
        if rule is None:
            continue
        if isinstance(rule, DetectionRule):
            reached = [name for name, sent in (tenant_targets or {}).items() if uuid in sent]
            previews.append(preview_rule_deployment(platform, rule, reached))
        else:
            previews.append(cast(dict[str, Any], rule))
    return previews
