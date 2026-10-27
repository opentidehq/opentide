"""``opentide explain``: what a diagnostic code means and how to fix it."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.output import emit_success, emit_usage_error, text_mode
from opentide.cli.ui.mode import OutputMode


def explain_cmd(
    ctx: typer.Context,
    code: str | None = typer.Argument(
        None, help="A diagnostic code, such as vocab_unknown. Omit it to list every code."
    ),
) -> None:
    """Explain a diagnostic code and how to fix it

    Prints what the code means, an example, and how to fix it.
    """
    from opentide.cli.services.explain import all_pages, diagnostic_codes, load_page

    cli = get_context(ctx)
    if code is None:
        pages = all_pages()
        if not cli.json_output:
            _render_index(pages)
        emit_success(
            cli,
            {
                "codes": [{"code": page.code, "meaning": page.summary} for page in pages],
                "message": f"{len(pages)} diagnostic codes",
                "_summary": {"codes": len(pages)},
            },
        )
        return
    page = load_page(code.strip())
    if page is None:
        emit_usage_error(
            cli,
            f"No diagnostic code {code!r}. Run 'opentide explain' to list them.",
            argument="code",
            value=code,
            choices=diagnostic_codes(),
        )
    if not cli.json_output:
        _render_page(page.markdown, human=text_mode(cli) is OutputMode.HUMAN)
        return
    emit_success(cli, {**page.to_dict(), "message": page.summary})


def _render_page(markdown: str, *, human: bool) -> None:
    from opentide.core.logging.config import get_stdout_console

    console = get_stdout_console()
    if human:
        from rich.markdown import Markdown

        console.print(Markdown(markdown))
    else:
        console.out(markdown.rstrip("\n"), highlight=False)


def _render_index(pages: list) -> None:
    from rich.text import Text

    from opentide.cli.ui.render import print_line
    from opentide.core.logging.config import get_stdout_console

    console = get_stdout_console()
    width = max((len(page.code) for page in pages), default=0)
    for page in pages:
        line = Text(f"{page.code:<{width}}  ", style="bold")
        line.append(page.summary, style="")
        # The summary continues under itself, between words (B44).
        print_line(console, line, hang=width + 2)
