"""``opentide lint``: catalogue hygiene."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.enums import LintCheck
from opentide.cli.output import CommandResult, emit_result
from opentide.cli.services.lint import render_findings, run_lint


def lint_cmd(
    ctx: typer.Context,
    fix: bool = typer.Option(False, "--fix", help="Apply safe filename renames"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when findings exist (CI gate)"
    ),
    check: list[LintCheck] = typer.Option(
        [], "--check", help="Limit to one check: filenames, metadata or placeholders (repeatable)"
    ),
) -> None:
    """Catalogue hygiene: filename slugs and recommended metadata (not schema validation)."""
    cli = get_context(ctx)
    cli.apply_environment()
    result = run_lint(cli.repo, checks=check or None, fix=fix, strict=strict)
    if not cli.json_output:
        render_findings(result["findings"])
    emit_result(cli, CommandResult.from_payload(result, default_message="Catalogue lint passed"))
