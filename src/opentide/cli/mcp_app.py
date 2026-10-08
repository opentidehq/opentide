"""``opentide mcp`` — stdio server the editor owns."""

from __future__ import annotations

import typer

mcp_app = typer.Typer(
    no_args_is_help=True,
    help=(
        "Run the OpenTide MCP server on stdio. The editor owns the process: "
        "stop is the host closing stdin, and reload is the host spawning this "
        "command again. There is no reload or stop subcommand."
    ),
)


@mcp_app.command("start")
def start() -> None:
    """Block on stdio until the host closes stdin. stdout is JSON-RPC only."""
    from opentide.mcp_server.launcher import main as serve

    serve()
