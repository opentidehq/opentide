"""``opentide rules`` commands."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.output import CommandResult, emit_error, emit_result
from opentide.cli.services.rules import render_unreviewed, run_unreviewed

rules_app = typer.Typer(help="Detection rule maintenance")


@rules_app.command("unreviewed")
def rules_unreviewed(
    ctx: typer.Context,
    older_than: str = typer.Option(
        "90d",
        "--older-than",
        help="Positive review window (90d, 12h, 30m). A review equal to T-W is fresh.",
    ),
) -> None:
    """List rules with no review date, or a review older than the window.

    ``rule::1.0`` is always listed. ``rule::1.1`` is listed when ``metadata.reviewed``
    is absent or strictly earlier than now minus the window. This command does not
    modify rules.
    """
    cli = get_context(ctx)
    cli.apply_environment()
    try:
        result = run_unreviewed(cli.repo, older_than=older_than)
    except ValueError as exc:
        emit_error(cli, str(exc))
    if not cli.json_output:
        render_unreviewed(result["rules"])
    emit_result(cli, CommandResult.from_payload(result))
