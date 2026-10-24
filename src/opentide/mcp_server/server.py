"""opentide MCP server — FastMCP entry point."""

from __future__ import annotations

import os
import sys
from collections.abc import Generator
from contextlib import contextmanager
from io import TextIOWrapper
from typing import TextIO

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
    "opentide",
    instructions=(
        "Detection engineering assistant. Search and analyse detection content, "
        "validate rules against their schema, check platform queries against the "
        "tenant when live is true, and dry-run rule deployment. Query execution "
        "against live platforms is not "
        "implemented: run_query never contacts a tenant and never returns rows."
    ),
)


@mcp.tool()
def search(
    query: str,
    type: str = "",
    platform: str = "",
    status: str = "",
    technique: str = "",
    actor: str = "",
) -> list[dict]:
    """Search the catalogue by keyword, UUID, or ATT&CK technique.

    Returns a list of ``{uuid, type, title, status}`` summaries; read
    ``opentide://rules/{uuid}`` for a full body.
    """
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
def validate_query(query: str, platform: str, live: bool = False) -> dict:
    """Tenant query check for the 5 query-capable platforms.

    The default refuses and does not scan ``query``. Pass ``live=True`` to check
    the catalogue rules for ``platform`` against the tenant. Unsupported platforms
    return ``valid: null``.
    """
    return tool_validate_query(query, platform, live=live)


@mcp.tool()
def run_query(query: str, platform: str, tenant: str = "") -> dict:
    """Not implemented — returns ``stub: true`` and never contacts a tenant.

    Use ``validate_query`` with ``live=True`` for the tenant check.
    """
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


@contextmanager
def reserve_stdout() -> Generator[TextIO, None, None]:
    """Keep the process's stdout for JSON-RPC alone while the server runs.

    Yields a stream on a duplicate of file descriptor 1 for the transport,
    then points descriptor 1 and ``sys.stdout`` at stderr. A ``print``, a Rich
    console, a child process or a C extension writing to stdout lands on
    stderr instead of corrupting a frame.
    """
    sys.stdout.flush()
    saved = sys.stdout
    rpc_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    rpc = TextIOWrapper(os.fdopen(rpc_fd, "wb"), encoding="utf-8")
    try:
        yield rpc
    finally:
        rpc.flush()
        os.dup2(rpc_fd, 1)
        sys.stdout = saved
        rpc.close()


async def serve_stdio() -> None:
    """``FastMCP.run_stdio_async``, writing frames to :func:`reserve_stdout`'s stream."""
    import anyio
    from mcp.server.stdio import stdio_server

    # Mirrors FastMCP.run_stdio_async (mcp 1.30), with our stdout stream passed in.
    with reserve_stdout() as rpc:
        async with stdio_server(stdout=anyio.wrap_file(rpc)) as (read_stream, write_stream):
            server = mcp._mcp_server  # noqa: SLF001 - what run_stdio_async drives
            await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    """Start the MCP server on stdio transport."""
    import anyio

    from opentide.cli.ui.mode import OutputMode, set_mode
    from opentide.core.logging import LoggingConfig, init_logging

    set_mode(OutputMode.MCP)
    # The Typer root callback already called init_logging. Without force the
    # CLI path would keep Rich-on-stderr and skip the JSON logs hosts parse.
    init_logging(LoggingConfig(json_output=True, plain=True), force=True)
    anyio.run(serve_stdio)


if __name__ == "__main__":
    main()
