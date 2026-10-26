"""``opentide lint``: catalogue hygiene."""

from __future__ import annotations

from pathlib import Path

import typer

from opentide.cli.context import get_context
from opentide.cli.enums import LintCheck
from opentide.cli.findings import (
    FORMAT_HELP,
    OUTPUT_HELP,
    check_report_options,
    print_report,
    publish_findings,
    write_report_file,
)
from opentide.cli.output import CommandResult, emit_result, text_mode
from opentide.cli.ui.reports import ReportFormat


def lint_cmd(
    ctx: typer.Context,
    fix: bool = typer.Option(False, "--fix", help="Apply safe filename renames"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when findings exist (CI gate)"
    ),
    check: list[LintCheck] = typer.Option(
        [],
        "--check",
        metavar="CHECK",
        help="Limit to one check: filenames, metadata or placeholders (repeatable)",
    ),
    report_format: ReportFormat = typer.Option(ReportFormat.text, "--format", help=FORMAT_HELP),
    output: Path | None = typer.Option(None, "--output", help=OUTPUT_HELP),
) -> None:
    """Check file names and recommended metadata

    Catalogue hygiene: filename slugs and recommended metadata, not schema validation.
    """
    from opentide.cli.services.lint import run_lint
    from opentide.cli.ui.diagnostics import SourceFiles, diagnostic_from_lint_finding

    cli = get_context(ctx)
    check_report_options(cli, report_format, output)
    cli.apply_environment()
    result = run_lint(cli.repo, checks=check or None, fix=fix, strict=strict)
    outcome = CommandResult.from_payload(result, default_message="Catalogue lint passed")
    if cli.json_output and report_format is ReportFormat.text:
        emit_result(cli, outcome)
        return
    root, sources = Path(str(result["path"])), SourceFiles()
    findings = result["findings"]
    diagnostics = [
        diagnostic_from_lint_finding(finding, root=root, sources=sources)
        for finding in (findings if isinstance(findings, list) else [])
    ]
    write_report_file(report_format, output, diagnostics, command="lint")
    if not cli.json_output:
        from opentide.cli.ui.codeframe import render_diagnostics
        from opentide.core.logging.config import get_stdout_console

        if report_format is not ReportFormat.text and output is None:
            print_report(report_format, diagnostics, outcome, command="lint")
        render_diagnostics(
            get_stdout_console(), diagnostics, sources=sources, mode=text_mode(cli), quiet=cli.quiet
        )
        publish_findings(
            cli, diagnostics, outcome, command="lint", outcome=outcome.outcome or outcome.message
        )
    emit_result(cli, outcome)
