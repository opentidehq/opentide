"""``opentide info``: repository and platform information."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.enums import PLATFORM_METAVAR, DetectionPlatform, platform_help
from opentide.cli.output import CommandResult, emit_result, emit_usage_error
from opentide.cli.services.info import collect_info, info_outcome, info_summary, render_info
from opentide.cli.ui.contract import ISSUES_FOUND, USAGE_MISSING_OPTION, NextAction


# ``info`` has no subcommands: the command index mounts it as a plain command,
# which keeps Click from treating options typed after the section
# (``info coverage --technique T1059``) as a subcommand name.
def info_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform | None = typer.Option(
        None, "--platform", metavar=PLATFORM_METAVAR, help=platform_help()
    ),
    section: str | None = typer.Argument(None),
    technique: str | None = typer.Option(
        None, "--technique", help="ATT&CK technique ID for the coverage section (T1059)"
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when any object failed to load"
    ),
) -> None:
    """Show repository and platform information"""
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
    summary = info_summary(result)
    result["_summary"] = summary
    result["_outcome"] = info_outcome(summary)
    if summary["load_errors"]:
        # The table counts the unreadable files; validate says why.
        result["_next_actions"] = [
            NextAction("opentide validate", "show where each object failed to load")
        ]
        result["status"] = "issues"
    if strict and summary["load_errors"]:
        result["status"] = "failed"
        result["message"] = "Repository has objects that failed to load"
        result["_exit_code"] = 1
        result["_failure_code"] = ISSUES_FOUND
    if not cli.json_output:
        render_info(result, section=section)
    emit_result(cli, CommandResult.from_payload(result))
