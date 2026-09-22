"""Console-script entry point for ``opentide-mcp``.

The script is installed by the base wheel, but ``mcp`` lives in the ``[mcp]``
extra: it pulls a web-server stack that a CI pipeline running
``opentide validate`` has no use for. Importing
:mod:`opentide.mcp_server.server` directly therefore dies with a bare
``ModuleNotFoundError``. This launcher turns that into the one instruction the
user needs.
"""

from __future__ import annotations

import importlib
import sys

#: Exact import the server performs at module scope. Checking the package name
#: alone is not enough: mcp 2.x is importable but dropped ``server.fastmcp``.
MCP_IMPORT = "mcp.server.fastmcp"

MCP_EXTRA = "opentide[mcp]"


def missing_requirements() -> list[str]:
    """Imports the MCP server needs that this interpreter cannot satisfy."""
    try:
        importlib.import_module(MCP_IMPORT)
    except ImportError:
        return [MCP_IMPORT]
    return []


def install_hint(missing: list[str]) -> str:
    packages = ", ".join(missing)
    return (
        f"opentide-mcp needs the MCP extra, which is not installed (missing: {packages}).\n"
        f"Install it with:  pip install '{MCP_EXTRA}'\n"
        f"Everything else in the opentide CLI works without it."
    )


def main() -> None:
    """Start the MCP server, or explain how to install it."""
    missing = missing_requirements()
    if missing:
        print(install_hint(missing), file=sys.stderr)
        raise SystemExit(1)
    from opentide.mcp_server.server import main as serve

    serve()


if __name__ == "__main__":
    main()
