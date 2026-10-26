"""``opentide lint``: catalogue hygiene."""

from __future__ import annotations

from pathlib import Path

import typer

from opentide.cli.context import get_context
from opentide.cli.enums import LintCheck
from opentide.cli.output import CommandResult, emit_result, text_mode
from opentide.cli.services.lint import run_lint


def lint_cmd(
    ctx: typer.Context,
    fix: bool = typer.Option(False, "--fix", help="Apply safe filename renames"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when findings exist (CI gate)"
    ),
    check: list[LintCheck] = typer.Option(
        [], "--check", help="Limit to one check: filenames or metadata (repeatable)"
    ),
) -> None:
    """Catalogue hygiene: filename slugs and recommended metadata (not schema validation)."""
    cli = get_context(ctx)
    cli.apply_environment()
    result = run_lint(cli.repo, checks=check or None, fix=fix, strict=strict)
    findings = result["findings"]
    if not cli.json_output and isinstance(findings, list):
        from opentide.cli.ui.codeframe import render_diagnostics
        from opentide.cli.ui.diagnostics import SourceFiles, diagnostic_from_lint_finding
        from opentide.core.logging.config import get_stdout_console

        root, sources = Path(str(result["path"])), SourceFiles()
        render_diagnostics(
            get_stdout_console(),
            [
                diagnostic_from_lint_finding(finding, root=root, sources=sources)
                for finding in findings
            ],
            sources=sources,
            mode=text_mode(cli),
            quiet=cli.quiet,
        )
    emit_result(cli, CommandResult.from_payload(result, default_message="Catalogue lint passed"))
