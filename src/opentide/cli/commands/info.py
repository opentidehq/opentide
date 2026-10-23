"""``opentide info``: repository and platform information."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.enums import PLATFORM_METAVAR, DetectionPlatform, platform_help
from opentide.cli.output import emit_success, emit_usage_error
from opentide.cli.services.info import collect_info, render_info
from opentide.cli.ui.contract import USAGE_MISSING_OPTION


# ``info`` has no subcommands: the command index mounts it as a plain command,
# which keeps Click from treating options typed after the section
# (``info coverage --technique T1059``) as a subcommand name.
def info_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform | None = typer.Option(
        None, "--platform", metavar=PLATFORM_METAVAR, help=platform_help()
    ),
    section: str | None = typer.Argument(None),
    technique: str | None = typer.Option(None, "--technique"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when any object failed to load"
    ),
) -> None:
    """Show repository and platform information."""
    cli = get_context(ctx)
    sections = ("rules", "threats", "objectives", "coverage")
    if section is not None and section not in sections:
        emit_usage_error(
            cli,
            f"Unknown info section: {section}. Choose {', '.join(sections)}.",
            argument="section",
            value=section,
            choices=sections,
        )
    if section == "coverage" and not technique:
        emit_usage_error(
            cli,
            "The coverage section requires --technique",
            argument="--technique",
            code=USAGE_MISSING_OPTION,
        )
    result = collect_info(cli, platform=platform, section=section, technique=technique)
    strict_failure = strict and int(result.get("parse_error_count") or 0) > 0
    if strict_failure:
        result["status"] = "failed"
        result["message"] = "Repository has objects that failed to load"
        result["_exit_code"] = 1
    if cli.json_output:
        emit_success(cli, result)
    else:
        render_info(result, section=section)
        if strict_failure:
            raise typer.Exit(1)
