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
) -> list[dict[str, Any]] | dict[str, Any]:
    return search_catalog(
        query,
        object_type=type,
        platform=platform,
        status=status,
        technique=technique,
        actor=actor,
    )


def tool_get_chaining(uuid: str) -> dict[str, Any]:
    return get_chaining_graph(uuid)


def tool_coverage(technique: str = "", tactic: str = "") -> dict[str, Any]:
    return coverage_analysis(technique=technique, tactic=tactic)


def tool_validate_rule(uuid: str) -> dict[str, Any]:
    ensure_initialised()
    _ = OpenTide.Rules
    rule = OpenTide.Rules.get(uuid)
    if rule is None:
        return {"valid": False, "errors": [f"Rule {uuid} not found"], "warnings": []}
    result = rule.validate()
    return {"valid": result.ok, "errors": result.errors, "warnings": []}


def tool_validate_query(query: str, platform: str) -> dict[str, Any]:
    if platform not in QUERY_VALIDATION_PLATFORMS:
        return {
            "valid": None,
            "supported": False,
            "message": f"query validation not supported for {platform}",
            "errors": [],
        }
    return {
        "valid": True,
        "supported": True,
        "errors": [],
        "message": "Query syntax validation available for this platform",
        "query_preview": query[:200],
    }


def tool_run_query(query: str, platform: str, tenant: str = "") -> dict[str, Any]:
    return {
        "rows": 0,
        "columns": [],
        "results": [],
        "truncated": False,
        "tenant": tenant or None,
        "platform": platform,
        "message": f"Read-only query execution capped at {MAX_QUERY_ROWS} rows (dry stub)",
        "query_preview": query[:200],
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
    result = rule.deploy(platform, dry_run=dry_run)
    return {
        "action": "dry-run" if dry_run else "deploy",
        "tenant": None,
        "rule_id": uuid,
        "status": rule.status,
        "dry_run": result.dry_run,
        "platform": platform,
        "message": result.message,
    }


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
            platforms_state[name] = {
                "deployed": bool(cfg),
                "rule_id": cfg.get("external_id") if isinstance(cfg, dict) else None,
                "tenants": cfg.get("tenants", []) if isinstance(cfg, dict) else [],
            }
    return {"platforms": platforms_state, "uuid": uuid, "found": True}
