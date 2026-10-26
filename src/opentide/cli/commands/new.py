"""``opentide new``: scaffold a threat, objective or rule from the generated template."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import NoReturn

import typer

from opentide.cli.context import CliContext, get_context
from opentide.cli.enums import DetectionPlatform
from opentide.cli.output import CommandResult, emit_error, emit_result
from opentide.cli.ui.contract import USAGE_EXIT_CODE, USAGE_NEEDS_INPUT, NextAction

#: ``failure.code`` when neither ``.opentide/`` nor ``objects/`` marks a workspace.
WORKSPACE_NOT_FOUND = "workspace_not_found"

new_app = typer.Typer(
    help=(
        "Scaffold a threat, objective or rule from its template\n\n"
        "The new file gets a fresh UUID, today's date, your git author and the "
        "catalogue's organisation, and is named the way opentide lint expects. "
        "Required values nobody has chosen yet are placeholders, listed in the "
        "output: replace them, then run opentide validate --file on the path."
    ),
    no_args_is_help=True,
)

_NAME_HELP = "Object name; the filename is its slug"
_PATH_HELP = "File to write, or a folder to write it in (default: the family's objects folder)"


def _can_prompt() -> bool:
    """Prompts are for a person at a terminal: ``human`` mode with a TTY on stdin."""
    from opentide.cli.ui.mode import OutputMode, get_mode

    return get_mode() is OutputMode.HUMAN and sys.stdin.isatty()


def _needs_input(cli: CliContext, family: str, missing: str) -> NoReturn:
    emit_error(
        cli,
        f"opentide new {family} needs {missing}; it prompts only at an interactive terminal",
        exit_code=USAGE_EXIT_CODE,
        code=USAGE_NEEDS_INPUT,
        argument=missing,
    )


def _ask_name(cli: CliContext, family: str, name: str | None) -> str:
    if name and name.strip():
        return name.strip()
    if not _can_prompt():
        _needs_input(cli, family, "--name")
    from opentide.cli.services.setup.interactive import ask_text

    answer = ask_text(f"{family.capitalize()} name").strip()
    if not answer:
        _needs_input(cli, family, "--name")
    return answer


def _ask_platforms(platforms: list[DetectionPlatform]) -> list[str]:
    """Platform blocks for a new rule. Asks only when none was given and a person can answer."""
    if platforms or not _can_prompt():
        return [platform.value for platform in platforms]
    from opentide.cli.enums import platform_label
    from opentide.cli.services.setup.interactive import ask_checkbox
    from opentide.platforms.enabled import enabled_systems

    enabled = enabled_systems()
    if not enabled:
        return []
    choices = [(platform_label(DetectionPlatform(key)), key) for key in enabled]
    return ask_checkbox("Platform blocks (space to select, enter for none)", choices)


def _run(
    ctx: typer.Context,
    family: str,
    name: str | None,
    *,
    path: str | None,
    platforms: list[DetectionPlatform] | None = None,
    objective: str | None = None,
    threats: list[str] | None = None,
) -> None:
    cli = get_context(ctx)
    cli.apply_environment()
    from opentide.core.root import is_workspace_root

    workspace = cli.repo.resolve()
    if not is_workspace_root(workspace):
        # Writing here would make this folder the workspace that every
        # directory below it discovers.
        emit_error(
            cli,
            f"No workspace at {workspace}: no .opentide/ or objects/ there or above it",
            code=WORKSPACE_NOT_FOUND,
            next_actions=[NextAction("opentide setup", "create a workspace first")],
        )
    resolved_name = _ask_name(cli, family, name)
    chosen = _ask_platforms(platforms or []) if family == "rule" else []

    from opentide.cli.services.generation import run_generate
    from opentide.cli.services.new import (
        TEMPLATE_MISSING,
        NewError,
        NewOptions,
        catalogue_organisation,
        git_author,
        missing_artifacts,
        scaffold_object,
        workspace_artifacts,
    )

    generated = missing_artifacts(workspace, family)
    if generated:
        outcome = run_generate(cli, phases=generated)
        if outcome.get("status") == "failed":
            emit_result(cli, CommandResult.from_payload(outcome))
        still = missing_artifacts(workspace, family)
        if still:
            artifacts = workspace_artifacts(workspace, family)
            emit_error(
                cli,
                f"opentide generate {' '.join(still)} did not write {artifacts.template.name} "
                f"and {artifacts.schema.name}",
                code=TEMPLATE_MISSING,
            )

    objects_root = workspace_artifacts(workspace, family).objects.parent
    options = NewOptions(
        family=family,
        name=resolved_name,
        platforms=tuple(dict.fromkeys(chosen)),
        objective=objective,
        threats=tuple(threats or ()),
        path=Path(path) if path else None,
    )
    try:
        payload = scaffold_object(
            workspace,
            options,
            author=git_author(workspace),
            organisation=catalogue_organisation(objects_root),
        )
    except NewError as error:
        emit_error(
            cli,
            str(error),
            exit_code=error.exit_code,
            code=error.code,
            argument=error.argument,
        )
    warnings: list[str] = list(payload.pop("warnings", []))
    if generated:
        # Not a warning: it is a step new took, and generate printed it.
        payload["generated"] = generated
    if options.platforms:
        from opentide.platforms.enabled import enable_platform_command, enabled_systems

        enabled = set(enabled_systems())
        warnings.extend(
            f"{platform} is not enabled in this workspace, so this block will not deploy; "
            f"enable it with '{enable_platform_command(platform)}'"
            for platform in options.platforms
            if platform not in enabled
        )
    if not payload.get("author"):
        warnings.append("No git user.name is set, so metadata.author is left out")
    if not payload.get("organisation"):
        warnings.append(
            "No object in the catalogue names an organisation, so metadata.organisation is left out"
        )
    if warnings:
        payload["warnings"] = warnings
    emit_result(cli, CommandResult.from_payload(payload))


@new_app.command("threat")
def new_threat(
    ctx: typer.Context,
    name: str | None = typer.Option(None, "--name", help=_NAME_HELP),
    path: str | None = typer.Option(None, "--path", help=_PATH_HELP),
) -> None:
    """Scaffold a threat."""
    _run(ctx, "threat", name, path=path)


@new_app.command("objective")
def new_objective(
    ctx: typer.Context,
    name: str | None = typer.Option(None, "--name", help=_NAME_HELP),
    threat: list[str] | None = typer.Option(
        None, "--threat", help="UUID of a threat this objective addresses (repeatable)"
    ),
    path: str | None = typer.Option(None, "--path", help=_PATH_HELP),
) -> None:
    """Scaffold a detection objective."""
    _run(ctx, "objective", name, path=path, threats=threat)


@new_app.command("rule")
def new_rule(
    ctx: typer.Context,
    name: str | None = typer.Option(None, "--name", help=_NAME_HELP),
    platform: list[DetectionPlatform] | None = typer.Option(
        None, "--platform", help="Add a configuration block for this platform (repeatable)"
    ),
    objective: str | None = typer.Option(
        None, "--objective", help="UUID of the objective this rule implements (detection_model)"
    ),
    path: str | None = typer.Option(None, "--path", help=_PATH_HELP),
) -> None:
    """Scaffold a detection rule."""
    _run(ctx, "rule", name, path=path, platforms=platform, objective=objective)
