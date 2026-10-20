"""Start path for ``opentide mcp start``.

``mcp`` is a base dependency of ``opentide`` (since 0.14.0), so a plain
``pip install opentide`` can start the server. When the import fails anyway the
cause is an incomplete environment or an incompatible ``mcp`` major, and
importing :mod:`opentide.mcp_server.server` directly would die with a bare
``ModuleNotFoundError``. This launcher turns that into the one instruction the
user needs, and it prints that line before any JSON-RPC.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys

#: Exact import the server performs at module scope. Checking the package name
#: alone is not enough: mcp 2.x is importable but dropped ``server.fastmcp``.
MCP_IMPORT = "mcp.server.fastmcp"
MCP_PACKAGE = "mcp"

MCP_SPECIFIER = "mcp>=1.28.1,<2"
#: Remedy for both failure modes. ``mcp`` is a base dependency since 0.14.0 and
#: opentide has no extras, so naming the package itself is the only advice that
#: changes anything.
MCP_INSTALL_HINT = f"pip install '{MCP_SPECIFIER}'"


def _package_installed(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def probe() -> str | None:
    """Why the MCP server cannot start here, or ``None`` when it can.

    ``mcp`` 2.x is importable but ships ``server.fastmcp`` as a stub that
    raises, so "not installed" would be a lie and the user would reinstall the
    extra they already have. Distinguish the two.
    """
    try:
        importlib.import_module(MCP_IMPORT)
    except ImportError as exc:
        if _package_installed(MCP_PACKAGE):
            return (
                f"opentide mcp start cannot use the installed mcp package: {exc}.\n"
                f"opentide needs {MCP_SPECIFIER}; mcp 2.x replaced "
                f"`{MCP_IMPORT}` with `MCPServer`.\n"
                f"Pin it with:  {MCP_INSTALL_HINT}"
            )
        return (
            f"opentide mcp start cannot import {MCP_IMPORT}, but mcp ships as a "
            f"base dependency of opentide — this environment is incomplete.\n"
            f"Repair it with:  {MCP_INSTALL_HINT}\n"
            f"Everything else in the opentide CLI works without it."
        )
    return None


def missing_requirements() -> list[str]:
    """Imports the MCP server needs that this interpreter cannot satisfy."""
    return [] if probe() is None else [MCP_IMPORT]


def main() -> None:
    """Start the MCP server, or explain how to install it."""
    problem = probe()
    if problem is not None:
        # Deliberately not `opentide.core.logging`: this runs before the MCP
        # stdio handshake and has to stay a plain stderr line a host will show.
        print(problem, file=sys.stderr)
        raise SystemExit(1)
    from opentide.mcp_server.server import main as serve

    serve()


if __name__ == "__main__":
    main()
