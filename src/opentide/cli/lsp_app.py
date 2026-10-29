"""``opentide lsp``: the language server, for editors.

opentide reports what the engine finds through its own verbs: ``validate``
(queries a platform would reject), ``validate query`` (query files too) and
``lint`` (query style). ``lsp`` only serves editors.
"""

from __future__ import annotations

import typer

lsp_app = typer.Typer(
    no_args_is_help=True,
    help=(
        "Serve the language server for editors\n\n"
        "The server is the analysis engine that pip install opentide installs: "
        "KQL, SPL, ES|QL, EQL, Kibana KQL, Lucene and Tide YAML. The editor owns "
        "the process and speaks the protocol on stdio. On the command line, "
        "opentide validate and opentide lint report what it finds."
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
