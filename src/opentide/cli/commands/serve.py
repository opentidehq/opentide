"""``opentide serve``: CLI commands in one warm process, for editors."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context


def serve_cmd(ctx: typer.Context) -> None:
    """Run CLI commands in one warm process, for editors

    JSON-RPC 2.0 on stdio, one message per line. Each run request executes a
    command as opentide --json would and answers with its document and exit
    code, without starting Python and rebuilding the registry each time. The
    editor owns the process: it ends on exit or when stdin closes. stdout
    carries the protocol only; logs go to stderr.
    """
    from opentide.cli import launch_environment
    from opentide.cli.services.serve import CommandRunner, serve_stdio

    cli = get_context(ctx)
    base = launch_environment()
    # Root options given to serve itself are every run's defaults.
    if cli.repo_explicit:
        base["OPENTIDE_REPO_ROOT"] = str(cli.repo)
        base["OPENTIDE_TIDE_WORKSPACE"] = str(cli.repo)
    if cli.data is not None:
        base["OPENTIDE_DATA_ROOT"] = str(cli.data)
    if cli.proxy:
        base["OPENTIDE_PROXY"] = cli.proxy
    if cli.debug:
        base["OPENTIDE_DEBUG"] = "1"
    code = serve_stdio(runner=CommandRunner(base_env=base))
    if code:
        raise typer.Exit(code)
