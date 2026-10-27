"""``opentide lsp`` — the language server, and its diagnostics on the command line."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import typer

lsp_app = typer.Typer(
    no_args_is_help=True,
    help=(
        "Run the opentide language server for editors\n\n"
        "The server is the analysis engine that pip install opentide installs: "
        "KQL, SPL, ES|QL, EQL, Kibana KQL, Lucene and Tide YAML. The editor owns "
        "the process and speaks the protocol on stdio; lsp check prints the same "
        "diagnostics on the command line."
    ),
)


@lsp_app.command("start")
def start(
    stdio: bool = typer.Option(
        False,
        "--stdio",
        help="Speak on stdin and stdout: the only transport, accepted for editors that pass it",
    ),
) -> None:
    """Serve the language server protocol on stdio until the editor closes stdin."""
    from opentide.cli.services.lsp import serve

    del stdio  # stdio is the only transport
    code = serve()
    if code:
        raise typer.Exit(code)


@lsp_app.command("check")
def check(
    ctx: typer.Context,
    paths: list[Path] | None = typer.Argument(
        None,
        metavar="[PATH]...",
        help="Files or folders to check. Default: every object file of the workspace",
        show_default=False,
    ),
    language: str | None = typer.Option(
        None,
        "--language",
        help="Read every file as this language (kql, spl, esql, eql, kuery, lucene, "
        "opentide-yaml). Default: from each file's extension",
    ),
    strict: bool = typer.Option(False, "--strict", help="Fail on warnings too"),
) -> None:
    """Print the diagnostics an editor shows for objects and query files."""
    from opentide.cli.context import get_context
    from opentide.cli.findings import publish_findings
    from opentide.cli.output import CommandResult, emit_result, text_mode
    from opentide.cli.services.lsp import run_lsp_check
    from opentide.cli.ui.codeframe import render_diagnostics
    from opentide.cli.ui.diagnostics import Diagnostic
    from opentide.core.logging.config import get_stdout_console

    cli = get_context(ctx)
    result: dict[str, Any] = run_lsp_check(cli, paths or [], language=language, strict=strict)
    diagnostics = cast("list[Diagnostic]", result.pop("_diagnostics", []))
    outcome = CommandResult.from_payload(result, default_message="Checked")
    if not cli.json_output:
        render_diagnostics(get_stdout_console(), diagnostics, mode=text_mode(cli), quiet=cli.quiet)
        publish_findings(
            cli,
            diagnostics,
            outcome,
            command="lsp check",
            outcome=outcome.outcome or outcome.message,
        )
    emit_result(cli, outcome)
