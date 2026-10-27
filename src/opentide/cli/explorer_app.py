"""``opentide explorer`` commands."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.output import emit_error, emit_success
from opentide.cli.services.explorer import run_explorer
from opentide.export.explorer_package import DEFAULT_EXPLORER_VERSION, EXPLORER_PACKAGE

explorer_app = typer.Typer(
    help=(
        "Corpus explorer: export the corpus, then build or serve it with the "
        f"{EXPLORER_PACKAGE} npm package (latest release unless --version names one). "
        "Needs Node.js 20.19+ on PATH."
    ),
    no_args_is_help=True,
)

_VERSION_HELP = f"{EXPLORER_PACKAGE} release to run: a version, range or dist-tag (0.5.0, ^0.5)"
_LATEST_HELP = f"Run the latest {EXPLORER_PACKAGE} release (the default)"


def _package_version(ctx: typer.Context, version: str | None, latest: bool) -> str | None:
    """``None`` for the default, else what was asked for; both at once is refused."""
    if version is not None and latest:
        emit_error(get_context(ctx), "Pass --version or --latest, not both", exit_code=2)
    return DEFAULT_EXPLORER_VERSION if latest else version


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
    version: str | None = typer.Option(None, "--version", help=_VERSION_HELP),
    latest: bool = typer.Option(False, "--latest", help=_LATEST_HELP),
) -> None:
    """Run `generate explorer`, then build the static explorer site."""
    cli = get_context(ctx)
    package_version = _package_version(ctx, version, latest)
    result = run_explorer(cli, "build", output=output, base_path=base_path, version=package_version)
    emit_success(cli, result)


@explorer_app.command("serve")
def explorer_serve(
    ctx: typer.Context,
    port: int = typer.Option(4173, "--port", min=0, max=65535, help="Port (0 picks a free one)"),
    host: str = typer.Option("127.0.0.1", "--host", help="Address to listen on"),
    output: str | None = typer.Option(
        None, "--output", help="Where the site is built (default: out/explorer in the repository)"
    ),
    version: str | None = typer.Option(None, "--version", help=_VERSION_HELP),
    latest: bool = typer.Option(False, "--latest", help=_LATEST_HELP),
) -> None:
    """Run `generate explorer`, build the explorer, and serve it until Ctrl-C."""
    cli = get_context(ctx)
    package_version = _package_version(ctx, version, latest)
    result = run_explorer(
        cli, "serve", output=output, port=port, host=host, version=package_version
    )
    emit_success(cli, result)
