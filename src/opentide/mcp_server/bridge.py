"""What the Python MCP server says of itself, for the Rust server (UC-3.7, #829).

``opentide mcp start`` serves MCP from Rust (rmcp, in
``crates/opentide-cli/src/mcp/``), which answers every tool and resource
itself (UC-6.0c, #841). What the server says of itself (its name,
instructions, capabilities, the tools' descriptions and schemas, the
resources and templates) is still this package's server's: :func:`manifest`
reads it from :mod:`opentide.mcp_server.server`, and
``scripts/build/mcp_manifest.py`` writes it to :data:`MANIFEST_PATH`, compiled
into the Rust server.
"""

from __future__ import annotations

from typing import Any

#: The Rust server's protocol for one answer: ``{"result": ...}`` or ``{"error": ...}``.
Answer = dict[str, Any]


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
