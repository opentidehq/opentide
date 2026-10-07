"""MCP tool implementations."""

from __future__ import annotations

from typing import Any

from opentide.core.registry import OpenTide
from opentide.mcp_server.catalog import (
    coverage_analysis,
    ensure_initialised,
    get_chaining_graph,
    search_catalog,
)
from opentide.mcp_server.constants import MAX_QUERY_ROWS, QUERY_VALIDATION_PLATFORMS


def tool_search(
    query: str,
    type: str = "",
    platform: str = "",
    status: str = "",
    technique: str = "",
    actor: str = "",
) -> list[dict[str, Any]]:
    return search_catalog(
        query, object_type=type, platform=platform, status=status, technique=technique, actor=actor
    )


def tool_get_chaining(uuid: str) -> dict[str, Any]:
    return get_chaining_graph(uuid)


def tool_coverage(technique: str = "", tactic: str = "") -> dict[str, Any]:
    return coverage_analysis(technique=technique, tactic=tactic)


def tool_validate_rule(uuid: str) -> dict[str, Any]:
    ensure_initialised()
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    _ = OpenTide.Rules
    rule = OpenTide.Rules.get(uuid)
    if rule is None:
        return {"valid": False, "errors": [f"Rule {uuid} not found"], "warnings": [], "issues": []}
    report = run_validation(scope=ValidationScope.narrow(uuids=frozenset({uuid})))
    return {
        "valid": report.ok,
        "errors": [issue.to_legacy_string() for issue in report.errors],
        "warnings": [issue.to_legacy_string() for issue in report.warnings],
        "issues": report.model_dump_json_ready().get("issues", []),
    }


def tool_validation_report(
    *,
    file: str | None = None,
    uuid: str | None = None,
    object_type: str | None = None,
) -> dict[str, Any]:
    """Structured validation report for agents (headless API)."""
    ensure_initialised()
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    scope = ValidationScope.full()
    if file or uuid or object_type:
        scope = ValidationScope.narrow(
            files=frozenset({file}) if file else None,
            uuids=frozenset({uuid}) if uuid else None,
            types=frozenset({object_type}) if object_type else None,
        )
    report = run_validation(scope=scope)
    return report.model_dump_json_ready()


def tool_validate_query(query: str, platform: str, live: bool = False) -> dict[str, Any]:
    """Tenant query check. The default refuses; ``live=True`` calls the tenant.

    ``live=True`` validates the catalogue rules for ``platform``, not ``query``.
    """
    if platform not in QUERY_VALIDATION_PLATFORMS:
        return {
            "valid": None,
            "supported": False,
            "mode": "unsupported",
            "message": f"query validation not supported for {platform}",
            "errors": [],
        }
    if not live:
        return {
            "valid": None,
            "supported": True,
            "status": "failed",
            "message": "Query validation checks the tenant. Pass live: true.",
            "query_preview": query[:200],
        }
    from opentide.cli.context import CliContext
    from opentide.cli.services.validation import validate_query_platform

    return validate_query_platform(CliContext(), platform, live=True)


def tool_run_query(query: str, platform: str, tenant: str = "") -> dict[str, Any]:
    """Not implemented. Never returns a row payload that looks like a real run."""
    if platform not in QUERY_VALIDATION_PLATFORMS:
        return {
            "supported": False,
            "stub": True,
            "rows": None,
            "platform": platform,
            "tenant": tenant or None,
            "message": f"query execution not supported for {platform}",
            "query_preview": query[:200],
        }
    return {
        "supported": True,
        "stub": True,
        "rows": None,
        "platform": platform,
        "tenant": tenant or None,
        "message": (
            "Read-only query execution is not implemented; no query was sent to "
            f"{platform}. The live path would cap results at {MAX_QUERY_ROWS} rows."
        ),
        "query_preview": query[:200],
    }


def _unknown_platform(uuid: str, platform: str, *, dry_run: bool) -> dict[str, Any]:
    return {
        "action": "error",
        "tenant": None,
        "rule_id": uuid,
        "status": "unknown_platform",
        "dry_run": dry_run,
        "platform": platform,
        "message": f"Unknown platform {platform!r}",
    }


def _missing_tenants(uuid: str, platform: str) -> dict[str, Any] | None:
    from opentide.platforms.enabled import MissingTenantsError, systems_without_tenants

    if platform not in systems_without_tenants([platform]):
        return None
    error = MissingTenantsError(platform)
    return {
        "action": "error",
        "tenant": None,
        "rule_id": uuid,
        "status": "failed",
        "dry_run": False,
        "platform": platform,
        "message": f"Cannot deploy: {error}",
        "advice": error.advice,
        "missing_tenants": {error.system: error.config_path},
    }


def tool_deploy_rule(uuid: str, platform: str, dry_run: bool = True) -> dict[str, Any]:
    ensure_initialised()
    _ = OpenTide.Rules
    rule = OpenTide.Rules.get(uuid)
    if rule is None:
        return {
            "action": "error",
            "tenant": None,
            "rule_id": uuid,
            "status": "not_found",
            "dry_run": dry_run,
        }
    if platform not in OpenTide.Platforms:
        return _unknown_platform(uuid, platform, dry_run=dry_run)
    if not dry_run:
        missing = _missing_tenants(uuid, platform)
        if missing is not None:
            return missing
    try:
        result = rule.deploy(platform, dry_run=dry_run)
    except ValueError as exc:
        return {
            "action": "error",
            "tenant": None,
            "rule_id": uuid,
            "status": "error",
            "dry_run": dry_run,
            "platform": platform,
            "message": str(exc),
        }
    return {
        "action": "dry-run" if dry_run else "deploy",
        "tenant": None,
        "rule_id": uuid,
        "status": rule.status,
        "dry_run": result.dry_run,
        "platform": platform,
        "message": result.message,
    }


def _platform_deployment_state(cfg: Any) -> dict[str, Any]:
    """A configuration block is not a completed deploy until an id or tenant is recorded."""
    if isinstance(cfg, dict):
        rule_id = cfg.get("external_id")
        tenants = cfg.get("tenants") or []
        if not isinstance(tenants, list):
            tenants = []
        deployed = rule_id is not None or bool(tenants)
    else:
        rule_id = None
        tenants = []
        deployed = False
    return {"deployed": deployed, "rule_id": rule_id, "tenants": tenants}


def tool_deployment_status(uuid: str) -> dict[str, Any]:
    ensure_initialised()
    body = OpenTide.Models.rules.get(uuid)
    if body is None:
        return {"platforms": {}, "uuid": uuid, "found": False}
    if not isinstance(body, dict):
        body = body.model_dump(by_alias=True) if hasattr(body, "model_dump") else {}
    platforms_state: dict[str, Any] = {}
    configs = body.get("configurations", {}) or body.get("platforms", {})
    if isinstance(configs, dict):
        for name, cfg in configs.items():
            platforms_state[name] = _platform_deployment_state(cfg)
    return {"platforms": platforms_state, "uuid": uuid, "found": True}
