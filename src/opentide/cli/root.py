"""The ``opentide`` root app: global options, and commands loaded on demand.

Commands are listed in :mod:`opentide.cli.commands` and defined in their own
modules; :class:`~opentide.cli.lazy.LazyTyperGroup` imports one only when it runs.
"""

from __future__ import annotations

import os

import typer

from opentide.cli.context import CliContext, sync_typer_rendering
from opentide.cli.lazy import LazyTyperGroup
from opentide.core.logging import LoggingConfig, init_logging
from opentide.core.root import get_repo_root

app = typer.Typer(
    name="opentide",
    cls=LazyTyperGroup,
    help="opentide — DetectionOps Engine",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _no_color_before_help(value: bool) -> bool:
    """Eager, so ``opentide --no-color --help`` is plain: help exits before callbacks."""
    if value:
        sync_typer_rendering(no_color=True)
    return value


def _print_version(value: bool) -> bool:
    """Eager, so ``opentide --version`` answers before the workspace is resolved.

    The console script answers ``--version`` before Typer is imported (see
    :func:`opentide.cli.main`); this covers ``app()`` called directly.
    """
    if value:
        from opentide import __version__

        typer.echo(f"opentide {__version__}")
        raise typer.Exit()
    return value


def _came_from_command_line(ctx: typer.Context, name: str) -> bool:
    """Whether *name* was typed as a flag rather than read from its envvar.

    Compared by name, not by enum identity: Typer bundles its own Click copy,
    so ``typer._click.core.ParameterSource`` is a different class from
    ``click.core.ParameterSource`` and ``==`` is always False.
    """
    source = ctx.get_parameter_source(name)
    return getattr(source, "name", "") == "COMMANDLINE"


#: Click's words for false; any other ``DEBUG`` value turns debug logging on.
_DEBUG_OFF = frozenset({"", "0", "f", "false", "n", "no", "off"})


def _debug_from_environment() -> bool:
    """Read ``DEBUG`` as a switch rather than a strict boolean.

    As the option's envvar, Click refused anything but a boolean word, so
    ``DEBUG=*`` or ``DEBUG=express:*`` (the Node ``debug`` package's
    convention, often exported shell-wide) failed every command with exit 2.
    """
    return os.environ.get("DEBUG", "").strip().lower() not in _DEBUG_OFF


@app.callback()
def main_callback(
    ctx: typer.Context,
    repo: str | None = typer.Option(
        None, "--repo", envvar="OPENTIDE_REPO_ROOT", help="Repository root"
    ),
    data: str | None = typer.Option(
        None, "--data", envvar="OPENTIDE_DATA_ROOT", help="Bundled data root"
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug logging. DEBUG set to anything but 0, false, no or off does too",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        is_eager=True,
        callback=_no_color_before_help,
        help="Disable Rich colour output",
    ),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
    proxy: str | None = typer.Option(
        None,
        "--proxy",
        envvar="OPENTIDE_PROXY",
        help=(
            "HTTP(S) proxy URL (http://\\[user:pass@\\]host:port) for platform and lookup "
            "calls. Overrides HTTP_PROXY and HTTPS_PROXY; hosts in NO_PROXY are still "
            "reached directly."
        ),
    ),
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        is_eager=True,
        callback=_print_version,
        help="Print the installed opentide version and exit",
    ),
) -> None:
    from pathlib import Path

    cli_ctx = CliContext(
        repo=Path(repo) if repo else get_repo_root(),
        data=Path(data) if data else None,
        json_output=json_output,
        debug=debug or _debug_from_environment(),
        no_color=no_color,
        repo_explicit=_came_from_command_line(ctx, "repo"),
        proxy=proxy,
    )
    ctx.obj = cli_ctx
    cli_ctx.activate()
    cli_ctx.apply_environment()
    init_logging(LoggingConfig.from_cli_context(cli_ctx), force=True)
