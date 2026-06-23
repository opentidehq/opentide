"""OpenTide MCP server — FastMCP entry point."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from opentide.mcp_server import resources as res
from opentide.mcp_server.tools import (
    tool_coverage,
    tool_deploy_rule,
    tool_deployment_status,
    tool_get_chaining,
    tool_run_query,
    tool_search,
    tool_validate_query,
    tool_validate_rule,
    tool_validation_report,
)

mcp = FastMCP(
    "OpenTide",
    instructions="Detection engineering assistant. Search and analyse detection content, validate rules and queries, test queries against live platforms, and deploy detection rules.",
)


@mcp.tool()
def search(
    query: str,
    type: str = "",
    platform: str = "",
    status: str = "",
    technique: str = "",
    actor: str = "",
) -> list[dict] | dict:
    """Search the catalogue by keyword, UUID, or ATT&CK technique."""
    return tool_search(
        query, type=type, platform=platform, status=status, technique=technique, actor=actor
    )


@mcp.tool()
def get_chaining(uuid: str) -> dict:
    """Return threat → objective → rule chaining graph."""
    return tool_get_chaining(uuid)


@mcp.tool()
def coverage(technique: str = "", tactic: str = "") -> dict:
    """ATT&CK coverage analysis with gap identification."""
    return tool_coverage(technique=technique, tactic=tactic)


@mcp.tool()
def validate_rule(uuid: str) -> dict:
    """Validate a rule against its schema."""
    return tool_validate_rule(uuid)


@mcp.tool()
def validation_report(
    file: str = "",
    uuid: str = "",
    object_type: str = "",
) -> dict:
    """Structured validation report (full registry by default; narrow with file/uuid/type)."""
    return tool_validation_report(
        file=file or None,
        uuid=uuid or None,
        object_type=object_type or None,
    )


@mcp.tool()
def validate_query(query: str, platform: str) -> dict:
    """Validate query syntax for supported platforms (5 of 7)."""
    return tool_validate_query(query, platform)


@mcp.tool()
def run_query(query: str, platform: str, tenant: str = "") -> dict:
    """Execute a read-only platform query (capped at 100 rows)."""
    return tool_run_query(query, platform, tenant=tenant)


@mcp.tool()
def deploy_rule(uuid: str, platform: str, dry_run: bool = True) -> dict:
    """Deploy a rule; defaults to dry-run."""
    return tool_deploy_rule(uuid, platform, dry_run=dry_run)


@mcp.tool()
def deployment_status(uuid: str) -> dict:
    """Show per-platform deployment state for a rule."""
    return tool_deployment_status(uuid)


@mcp.resource("opentide://index")
def index_resource() -> str:
    return res.resource_index()


@mcp.resource("opentide://rules")
def rules_resource() -> str:
    return res.resource_rules()


@mcp.resource("opentide://rules/{uuid}")
def rule_resource(uuid: str) -> str:
    return res.resource_rule(uuid)


@mcp.resource("opentide://threats")
def threats_resource() -> str:
    return res.resource_threats()


@mcp.resource("opentide://threats/{uuid}")
def threat_resource(uuid: str) -> str:
    return res.resource_threat(uuid)


@mcp.resource("opentide://objectives")
def objectives_resource() -> str:
    return res.resource_objectives()


@mcp.resource("opentide://objectives/{uuid}")
def objective_resource(uuid: str) -> str:
    return res.resource_objective(uuid)


@mcp.resource("opentide://schemas/{object_type}")
def schema_resource(object_type: str) -> str:
    return res.resource_schema(object_type)


@mcp.resource("opentide://templates/{object_type}")
def template_resource(object_type: str) -> str:
    return res.resource_template(object_type)


@mcp.resource("opentide://vocabularies")
def vocabularies_resource() -> str:
    return res.resource_vocabularies()


@mcp.resource("opentide://vocabularies/{name}")
def vocabulary_resource(name: str) -> str:
    return res.resource_vocabulary(name)


@mcp.resource("opentide://platforms")
def platforms_resource() -> str:
    return res.resource_platforms()


def main() -> None:
    """Start the MCP server on stdio transport."""
    from opentide.core.logging import LoggingConfig, init_logging

    init_logging(LoggingConfig(json_output=True, plain=True))
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
