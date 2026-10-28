"""opentide MCP server — MCPServer (mcp 2.x) entry point.

Tool docstrings are the descriptions an agent reads in ``tools/list``: each
says what the tool returns, which keys to branch on, and what to call next.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Generator
from contextlib import contextmanager
from io import TextIOWrapper
from typing import TextIO

from mcp.server.mcpserver import MCPServer

import opentide
from opentide.analysis import OFFLINE_QUERY_LANGUAGES
from opentide.mcp_server import resources as res
from opentide.mcp_server.constants import QUERY_VALIDATION_PLATFORMS
from opentide.mcp_server.tools import (
    tool_coverage,
    tool_deploy_rule,
    tool_deployment_status,
    tool_explain,
    tool_get_chaining,
    tool_run_query,
    tool_search,
    tool_validate_query,
    tool_validate_rule,
    tool_validation_report,
)

#: What the product is, wherever it describes itself.
TAGLINE = "Spec-driven development for agentic detection engineering"

INSTRUCTIONS = f"""\
opentide: {TAGLINE}. opentide gives every detection an ontology and a taxonomy, \
so it stays threat-aligned, maintainable and fast to ship, with or without agents.

The catalogue is YAML in the repository: threats (objects/threats/), objectives \
(objects/objectives/) and rules (objects/rules/). A rule's detection_model is an \
objective UUID; an objective lists threat UUIDs.

Workflow:
1. Search. search (keyword, UUID, technique) and coverage find what exists; \
get_chaining shows threat -> objective -> rule.
2. Draft. Start from opentide://templates/{{object_type}}, check fields against \
opentide://schemas/{{object_type}} and opentide://vocabularies/{{name}}, and write the \
file with your own tools: this server does not write files.
3. Validate until clean. Call validation_report with file or uuid after every edit. \
Each issue has code, severity, message, object_uuid, path, line and column (1-based), \
help, and fix ({{safe, edits}}: each edit replaces the text from (line, column) up \
to (end_line, end_column) with replacement). Apply safe edits as they are: they \
only respell the same word; check the others against help. explain(code) says what \
a code means. Repeat until ok is true. While drafting a query, validate_query \
checks it offline in its platform's language, with no tenant.
4. Preview. deploy_rule with dry_run true shows the deployment; nothing is sent.

People review and merge changes and run real deployments. Call deploy_rule with \
dry_run false only when a person asks for it. validate_query with live true \
contacts the tenant with the configured credentials: ask first. run_query is not \
implemented and never returns rows.

Results may carry next_actions: [{{tool, arguments, command, reason}}], the next \
call to make (command is the same step as an opentide command line). Read the \
reason before following one.\
"""

mcp = MCPServer(
    "opentide",
    # Without it mcp 2.x reports serverInfo.version as "".
    version=opentide.__version__,
    instructions=INSTRUCTIONS,
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
    """Find threats, objectives and rules. Start here when you have no UUID.

    query: a UUID (exact, case-insensitive) or text matched against uuid, title,
    name and description; "" matches everything the filters allow.
    Filters: type (rule | threat | objective), platform (exact configuration key:
    sentinel never matches sentinel_one), status (rule status, exact), technique
    (ATT&CK id, case-insensitive), actor (att&ck::G0006 or G0006).
    Returns a list of {uuid, type, title, status}; [] when nothing matches.
    Read opentide://rules/{uuid} (threats/, objectives/) for the full object.
    """
    return tool_search(
        query, type=type, platform=platform, status=status, technique=technique, actor=actor
    )


@mcp.tool()
def get_chaining(uuid: str) -> dict:
    """Threat -> objective -> rule lineage of any object, before you edit or add one.

    Returns {uuid, found, type, graph, lineage: {threats, objectives, rules},
    chaining_index}. graph is the lineage, or {relation: [threat uuids]} for a
    threat with threat.chaining entries. An unknown UUID returns only {uuid,
    found: false, graph: {}}.
    """
    return tool_get_chaining(uuid)


@mcp.tool()
def coverage(technique: str = "", tactic: str = "") -> dict:
    """ATT&CK coverage: which rules detect a technique, and where the gaps are.

    technique (T1059): {technique, covered, matched_techniques, rules}; a parent
    technique also matches its sub-techniques. Empty: {technique_count, matrix:
    {technique: [rule uuids]}, tactic_filter}. tactic is echoed, never filtered on.
    """
    return tool_coverage(technique=technique, tactic=tactic)


@mcp.tool()
def validate_rule(uuid: str) -> dict:
    """Validate one rule by UUID: schema, vocabularies and references.

    Returns {valid, errors, warnings, issues, next_actions}. errors and warnings
    are strings; issues are structured like validation_report's. Prefer
    validation_report, which also takes a file path and returns warnings as
    structured entries.
    """
    return tool_validate_rule(uuid)


@mcp.tool()
def validation_report(
    file: str = "",
    uuid: str = "",
    object_type: str = "",
    queries: str = "error",
) -> dict:
    """Validate objects and return every issue with its position and fix. Call after each edit.

    Narrow with file (repository-relative or absolute path; a bare file name
    matches every object file of that name), uuid, or object_type (rule |
    threat | objective). No argument validates the whole catalogue. Every
    rule query is checked offline: queries is error (a query the platform
    would reject is an issue), warn (a warning) or off (not checked).
    Returns {ok, issues, warnings, stats, next_actions}. Each issue: code,
    severity, message, object_uuid, field_path, path, line, column, end_column
    (1-based Unicode code points; end_column exclusive), help, fix ({safe,
    edits: [{line, column, end_line, end_column, replacement}]} or null),
    explain. safe edits only respell the same word; check the others against
    help. yaml_line is 0-based and file_path absolute, kept for older clients.
    Done when ok is true.
    """
    return tool_validation_report(
        file=file or None,
        uuid=uuid or None,
        object_type=object_type or None,
        queries=queries,
    )


@mcp.tool()
def explain(code: str = "") -> dict:
    """What a diagnostic code means, an example, and how to fix it.

    code: an issue's code, such as vocab_unknown. Returns {found, code, meaning,
    markdown}. An unknown code returns found false and the closest code as
    suggestion. Empty: {found, codes: [{code, meaning}]}, every code.
    """
    return tool_explain(code)


#: The platform list comes from the constant the tool checks, so the two cannot disagree.
VALIDATE_QUERY_DESCRIPTION = f"""\
Check one query offline with the analysis engine, or the catalogue's rules on the tenant.

live false (default) parses query in its platform's language, with the
platform's profile (Defender tables for defender_for_endpoint, Carbon Black
Lucene for carbon_black_cloud), and returns {{valid, status, language,
errors, warnings, diagnostics}}; positions are in the query (1-based, code
points). Elastic takes language: esql, eql, kuery (default) or lucene, and
stack (such as "9.5") for ES|QL. Offline: {", ".join(sorted(OFFLINE_QUERY_LANGUAGES))}.
live true contacts the tenant with the configured credentials and validates
the catalogue rules for platform, not query; ask a person first.
Platforms: {", ".join(sorted(QUERY_VALIDATION_PLATFORMS))}; others return
supported false.\
"""


@mcp.tool(description=VALIDATE_QUERY_DESCRIPTION)
def validate_query(
    query: str, platform: str, live: bool = False, language: str = "", stack: str = ""
) -> dict:
    """See :data:`VALIDATE_QUERY_DESCRIPTION`, the description agents read."""
    return tool_validate_query(query, platform, live=live, language=language, stack=stack)


@mcp.tool()
def run_query(query: str, platform: str, tenant: str = "") -> dict:
    """Not implemented: returns stub true and rows null, and never contacts a tenant.

    Use validate_query with live true for the tenant check.
    """
    return tool_run_query(query, platform, tenant=tenant)


@mcp.tool()
def deploy_rule(uuid: str, platform: str, dry_run: bool = True) -> dict:
    """Preview one rule's deployment to a platform. dry_run false deploys it for real.

    Returns {action: dry-run | deploy | error, rule_id, status, dry_run, platform,
    message}. When nothing was deployed, action is error and status is failed,
    not_found or unknown_platform. Keep dry_run true unless a person asks for a
    real deployment: people review, merge and deploy.
    """
    return tool_deploy_rule(uuid, platform, dry_run=dry_run)


@mcp.tool()
def deployment_status(uuid: str) -> dict:
    """Where a rule is deployed: vendor ids and tenants per platform.

    Returns {uuid, found, platforms: {name: {deployed, rule_id, external_ids,
    tenants}}}; state_error when the rule's deployment state cannot be read.
    """
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


# `{+name}`, not `{name}`: mcp 2.x matches RFC 6570, where a simple expansion
# rejects a literal `&`, and the index advertises `opentide://vocabularies/att&ck`.
# Reserved expansion accepts that and the percent-encoded `att%26ck` alike.
@mcp.resource("opentide://vocabularies/{+name}")
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
    """``MCPServer.run_stdio_async``, writing frames to :func:`reserve_stdout`'s stream."""
    import anyio
    from mcp.server.stdio import stdio_server

    # Mirrors MCPServer.run_stdio_async (mcp 2.3), with our stdout stream passed in.
    with reserve_stdout() as rpc:
        async with stdio_server(stdout=anyio.wrap_file(rpc)) as (read_stream, write_stream):
            server = mcp._lowlevel_server
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
