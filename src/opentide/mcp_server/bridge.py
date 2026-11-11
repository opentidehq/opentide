"""The Python half of the Rust MCP server (UC-3.7, #829).

``OPENTIDE_ENGINE=rust opentide mcp start`` serves MCP from Rust (rmcp, in
``crates/opentide-cli/src/mcp/``), in this Python process: the Rust command
line runs in it through ``opentide._native.cli_main``. The tools and resources
whose Rust implementation does not exist yet are handed to this module, in
process, and answered by the Python server's own handlers
(:mod:`opentide.mcp_server.server`), so their answers are the Python
server's, error for error. The Rust server calls:

- :func:`start` once, before it answers anything: the Python server's own
  start-up (output mode, the Agent Plugin launch, logging);
- :func:`workspace_problem`: why there is no workspace to serve, if so;
- :func:`call_tool` and :func:`read_resource`: one request each, as the JSON
  of the JSON-RPC ``result``, or of the ``error``.

Which tool runs where is ``DELEGATED_TOOLS`` in ``crates/opentide-cli/src/mcp/mod.rs``.
"""

from __future__ import annotations

import json
from typing import Any

#: The Rust server's protocol for one answer: ``{"result": ...}`` or ``{"error": ...}``.
Answer = dict[str, Any]


def start() -> None:
    """What the Python server does before it serves: ``server.main`` without the transport."""
    from opentide.cli.ui.mode import OutputMode, set_mode
    from opentide.core.logging import LoggingConfig, init_logging
    from opentide.mcp_server.workspace import apply_plugin_launch, resolve_plugin_launch

    set_mode(OutputMode.MCP)
    apply_plugin_launch(resolve_plugin_launch())
    init_logging(LoggingConfig(json_output=True, plain=True), force=True)


def workspace_problem() -> str | None:
    """The ``workspace_not_found`` message the catalogue tools refuse with, or ``None``."""
    from mcp.server.mcpserver.exceptions import ToolError

    from opentide.mcp_server import workspace

    try:
        workspace.require_workspace()
    except ToolError as exc:
        return str(exc)
    return None


def call_tool(name: str, arguments: str) -> str:
    """``tools/call`` *name* with *arguments* (a JSON object) on the Python server."""
    from mcp.types import CallToolRequestParams

    from opentide.mcp_server.server import mcp

    params = CallToolRequestParams(name=name, arguments=json.loads(arguments))
    return json.dumps(_answer(mcp._handle_call_tool, params))


def read_resource(uri: str) -> str:
    """``resources/read`` *uri* on the Python server."""
    from mcp.types import ReadResourceRequestParams

    from opentide.mcp_server.server import mcp

    params = ReadResourceRequestParams(uri=uri)
    return json.dumps(_answer(mcp._handle_read_resource, params))


def _answer(handler: Any, params: Any) -> Answer:
    """Run one of the SDK's request handlers as its request loop does; the answer's wire form."""
    import anyio
    from mcp.shared.jsonrpc_dispatcher import handler_exception_to_error_data
    from mcp.types import ErrorData

    try:
        result = anyio.run(handler, None, params)
    except Exception as exc:
        error = handler_exception_to_error_data(exc) or ErrorData(code=0, message=str(exc))
        return {"error": error.model_dump(by_alias=True, mode="json", exclude_none=True)}
    return {"result": result.model_dump(by_alias=True, mode="json", exclude_none=True)}


#: Where the Rust server reads what :func:`manifest` returns, relative to the repository root.
MANIFEST_PATH = "crates/opentide-cli/data/mcp/manifest.json"


def manifest() -> dict[str, Any]:
    """What the Python server says of itself, as the Rust server serves it.

    ``initialize``'s name, instructions, capabilities and the protocol
    version it falls back to, and the ``tools/list``, ``resources/list`` and
    ``resources/templates/list`` results, in their wire form.
    ``scripts/build/mcp_manifest.py`` writes it to :data:`MANIFEST_PATH`,
    compiled into the Rust server; ``tests/test_mcp/test_bridge.py`` fails
    when that copy is stale.
    """
    from mcp_types.version import LATEST_HANDSHAKE_VERSION

    from opentide.mcp_server.server import mcp

    low = mcp._lowlevel_server
    options = low.create_initialization_options()
    lists = {
        "tools": mcp._handle_list_tools,
        "resources": mcp._handle_list_resources,
        "resourceTemplates": mcp._handle_list_resource_templates,
    }
    out: dict[str, Any] = {
        "name": options.server_name,
        "instructions": options.instructions,
        "capabilities": _capabilities(options.capabilities),
        "protocolVersion": LATEST_HANDSHAKE_VERSION,
    }
    for key, handler in lists.items():
        answer = _answer(handler, None)
        result = answer["result"]
        out[key] = result[key]
    return out


def _capabilities(capabilities: Any) -> dict[str, Any]:
    """The capabilities as ``initialize`` answers them: without an empty ``extensions``."""
    dumped = capabilities.model_dump(by_alias=True, mode="json", exclude_none=True)
    if not dumped.get("extensions"):
        dumped.pop("extensions", None)
    return dumped
