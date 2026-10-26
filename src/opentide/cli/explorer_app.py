"""``opentide explorer`` commands."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.output import emit_success
from opentide.cli.services.explorer import run_explorer
from opentide.export.explorer_package import explorer_package_spec

explorer_app = typer.Typer(
    help=(
        "Corpus explorer: export the corpus, then build or serve it with the "
        f"{explorer_package_spec()} npm package. Needs Node.js 20.19+ on PATH."
    ),
    no_args_is_help=True,
)


@explorer_app.command("build")
def explorer_build(
    ctx: typer.Context,
    output: str | None = typer.Option(
        None, "--output", help="Static site directory (default: out/explorer in the repository)"
    ),
    base_path: str | None = typer.Option(
        None,
        "--base-path",
        help="URL prefix the site is served under, e.g. /my-repo for GitHub Pages",
    ),
) -> None:
    """Run `generate explorer`, then build the static explorer site."""
    cli = get_context(ctx)
    emit_success(cli, run_explorer(cli, "build", output=output, base_path=base_path))


@explorer_app.command("serve")
def explorer_serve(
    ctx: typer.Context,
    port: int = typer.Option(4173, "--port", min=0, max=65535, help="Port (0 picks a free one)"),
    host: str = typer.Option("127.0.0.1", "--host", help="Address to listen on"),
    output: str | None = typer.Option(
        None, "--output", help="Where the site is built (default: out/explorer in the repository)"
    ),
) -> None:
    """Run `generate explorer`, build the explorer, and serve it until Ctrl-C."""
    cli = get_context(ctx)
    emit_success(cli, run_explorer(cli, "serve", output=output, port=port, host=host))
