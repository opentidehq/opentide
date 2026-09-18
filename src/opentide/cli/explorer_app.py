"""Typer application for ``opentide explorer``."""

from __future__ import annotations

from pathlib import Path

import typer

from opentide.cli.context import get_context
from opentide.cli.output import emit_error, emit_success
from opentide.cli.services.explorer import (
    ExplorerSourceOptions,
    run_explorer_build,
    run_explorer_dev,
    run_explorer_serve,
)

explorer_app = typer.Typer(
    help="Build, preview, and serve the OpenTide explorer static UI",
    no_args_is_help=True,
)


def _source_options(
    *,
    explorer_path: Path | None,
    explorer_git: str | None,
    explorer_ref: str | None,
    version: str | None,
    repo: Path,
) -> ExplorerSourceOptions:
    return ExplorerSourceOptions(
        explorer_path=explorer_path,
        explorer_git=explorer_git,
        explorer_ref=explorer_ref,
        version=version,
        repo_root=repo,
    )


@explorer_app.command("build")
def explorer_build_cmd(
    ctx: typer.Context,
    output: Path | None = typer.Option(None, "--output", help="Static site output directory"),
    base_path: str = typer.Option(
        "", "--base-path", help="Next.js basePath (for example /library)"
    ),
    exports_dir: Path | None = typer.Option(
        None, "--exports-dir", help="Directory with explorer.*.json"
    ),
    schemas_dir: Path | None = typer.Option(None, "--schemas-dir", help="JSON Schema directory"),
    skip_install: bool = typer.Option(False, "--skip-install", help="Skip pnpm install"),
    explorer_path: Path | None = typer.Option(
        None, "--explorer-path", envvar="OPENTIDE_EXPLORER_PATH", help="Local explorer checkout"
    ),
    explorer_git: str | None = typer.Option(
        None, "--explorer-git", envvar="EXPLORER_GIT_URL", help="Git URL to shallow-clone"
    ),
    explorer_ref: str | None = typer.Option(
        None, "--explorer-ref", envvar="EXPLORER_GIT_REF", help="Git branch, tag, or commit"
    ),
    version: str | None = typer.Option(
        None, "--version", envvar="EXPLORER_VERSION", help="Explorer git ref (cache clone)"
    ),
) -> None:
    """Generate explorer exports and build the static site."""
    cli = get_context(ctx)
    cli.apply_environment()
    try:
        result = run_explorer_build(
            output=output,
            base_path=base_path,
            exports_dir=exports_dir,
            schemas_dir=schemas_dir,
            skip_install=skip_install,
            source_options=_source_options(
                explorer_path=explorer_path,
                explorer_git=explorer_git,
                explorer_ref=explorer_ref,
                version=version,
                repo=cli.repo,
            ),
        )
    except (FileNotFoundError, RuntimeError) as exc:
        emit_error(cli, str(exc))
    emit_success(cli, result)


@explorer_app.command("dev")
def explorer_dev_cmd(
    ctx: typer.Context,
    exports_dir: Path | None = typer.Option(
        None, "--exports-dir", help="Directory with explorer.*.json"
    ),
    skip_install: bool = typer.Option(False, "--skip-install", help="Skip pnpm install"),
    explorer_path: Path | None = typer.Option(
        None, "--explorer-path", envvar="OPENTIDE_EXPLORER_PATH", help="Local explorer checkout"
    ),
    explorer_git: str | None = typer.Option(
        None, "--explorer-git", envvar="EXPLORER_GIT_URL", help="Git URL to shallow-clone"
    ),
    explorer_ref: str | None = typer.Option(
        None, "--explorer-ref", envvar="EXPLORER_GIT_REF", help="Git branch, tag, or commit"
    ),
    version: str | None = typer.Option(
        None, "--version", envvar="EXPLORER_VERSION", help="Explorer git ref (cache clone)"
    ),
) -> None:
    """Preview the explorer UI with a local Next.js dev server."""
    cli = get_context(ctx)
    cli.apply_environment()
    try:
        result = run_explorer_dev(
            exports_dir=exports_dir,
            skip_install=skip_install,
            source_options=_source_options(
                explorer_path=explorer_path,
                explorer_git=explorer_git,
                explorer_ref=explorer_ref,
                version=version,
                repo=cli.repo,
            ),
        )
    except (FileNotFoundError, RuntimeError) as exc:
        emit_error(cli, str(exc))
    emit_success(cli, result)


@explorer_app.command("serve")
def explorer_serve_cmd(
    ctx: typer.Context,
    output: Path | None = typer.Option(None, "--output", help="Built static site directory"),
    port: int = typer.Option(4173, "--port", help="HTTP port"),
) -> None:
    """Serve a previously built explorer static directory."""
    cli = get_context(ctx)
    cli.apply_environment()
    try:
        result = run_explorer_serve(
            output=output,
            port=port,
            source_options=_source_options(
                explorer_path=None,
                explorer_git=None,
                explorer_ref=None,
                version=None,
                repo=cli.repo,
            ),
        )
    except (FileNotFoundError, RuntimeError) as exc:
        emit_error(cli, str(exc))
    emit_success(cli, result)
