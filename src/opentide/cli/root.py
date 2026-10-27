"""The ``opentide`` root app: global options, and commands loaded on demand.

Commands are listed in :mod:`opentide.cli.commands` and defined in their own
modules; :class:`~opentide.cli.lazy.LazyTyperGroup` imports one only when it runs.
"""

from __future__ import annotations

import typer

from opentide.cli.context import CliContext, sync_typer_rendering
from opentide.cli.help import epilog
from opentide.cli.lazy import LazyTyperGroup
from opentide.core.logging import LoggingConfig, init_logging
from opentide.core.root import get_repo_root

app = typer.Typer(
    name="opentide",
    cls=LazyTyperGroup,
    help="Spec-driven development for agentic detection engineering",
    epilog=epilog(""),
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


@app.callback()
def main_callback(
    ctx: typer.Context,
    repo: str | None = typer.Option(
        None, "--repo", envvar="OPENTIDE_REPO_ROOT", help="Repository root"
    ),
    data: str | None = typer.Option(
        None, "--data", envvar="OPENTIDE_DATA_ROOT", help="Bundled data root"
    ),
    # No envvar here: Click would reject DEBUG='*' (Node tooling exports it) as
    # an invalid boolean and fail every command. OPENTIDE_DEBUG, and DEBUG when
    # it is a boolean literal, are read in the callback instead.
    debug: bool = typer.Option(
        False, "--debug", help="Enable debug logging. Also OPENTIDE_DEBUG=1"
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Print only the outcome line and errors"),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        is_eager=True,
        callback=_no_color_before_help,
        help="Disable colour",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Machine-readable output: one JSON object on stdout"
    ),
    proxy: str | None = typer.Option(
        None,
        "--proxy",
        envvar="OPENTIDE_PROXY",
        help=(
            "HTTP(S) proxy URL (http://\\[user:pass@]host:port) for platform and lookup "
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

    from opentide.cli.lazy import COMMAND_WORDS_KEY
    from opentide.cli.ui.mode import OutputMode, resolve_mode, set_mode
    from opentide.core.runtime import debug_requested

    mode = set_mode(
        resolve_mode(
            json_flag=json_output,
            no_color=no_color,
            command=ctx.meta.get(COMMAND_WORDS_KEY, ()),
        )
    )
    cli_ctx = CliContext(
        repo=Path(repo) if repo else get_repo_root(),
        data=Path(data) if data else None,
        json_output=mode is OutputMode.JSON,
        debug=debug or debug_requested(),
        no_color=no_color,
        quiet=quiet,
        repo_explicit=_came_from_command_line(ctx, "repo"),
        proxy=proxy,
    )
    ctx.obj = cli_ctx
    cli_ctx.activate()
    cli_ctx.apply_environment()
    init_logging(LoggingConfig.from_cli_context(cli_ctx), force=True)
    words = tuple(ctx.meta.get(COMMAND_WORDS_KEY, ()))
    # A mistyped --repo used to read as an empty workspace: validate passed
    # ("no detection objects were found") and a CI job went green. setup is
    # the one command that may name a folder it is about to create.
    if cli_ctx.repo_explicit and words[:1] != ("setup",) and not cli_ctx.repo.is_dir():
        from opentide.cli.output import emit_usage_error
        from opentide.cli.ui.contract import USAGE_INVALID_VALUE, NextAction

        problem = "is not a directory" if cli_ctx.repo.exists() else "does not exist"
        # The failure line alone left no step (post-merge AFTER shots). Not a
        # re-run without --repo: the words drop options such as --dry-run.
        steps = (NextAction("opentide --help", "--repo takes the folder with .opentide/ in it"),)
        emit_usage_error(
            cli_ctx,
            f"--repo {repo} {problem}",
            argument="--repo",
            code=USAGE_INVALID_VALUE,
            next_actions=steps,
        )
