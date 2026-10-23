"""Rich presentation helpers for section headers and fatal errors."""

from __future__ import annotations

import warnings

from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from opentide.core.logging.config import (
    current_config,
    get_console,
    get_logger,
    is_json_output,
    is_plain_output,
)


def emit_section(title: str) -> None:
    """Render a section header (nothing under ``--quiet``).

    While a CLI checklist is showing progress the title becomes the stage of
    its running step instead (:func:`opentide.core.progress.report_stage`).
    Engine modules report stages directly and no longer call this.
    """
    from opentide.core import progress

    if progress.is_listening():
        progress.report_stage(title)
        return
    if is_json_output():
        get_logger("opentide").info("section_started", section=title)
        return
    if current_config().quiet:
        return

    console = get_console()
    if is_plain_output():
        console.print(f"\n== {title} ==\n", markup=False)
        return

    console.rule(f"[bold cyan]{escape(title)}[/]")


def emit_fatal(message: str, *, detail: str = "", advice: str = "") -> None:
    """Render a fatal error panel.

    The CLI no longer uses this for ordinary failures, which print an
    ``error:`` line (:func:`opentide.cli.output.emit_result`).
    """
    if is_json_output():
        logger = get_logger("opentide")
        payload: dict[str, str] = {}
        if detail:
            payload["detail"] = detail
        if advice:
            payload["advice"] = advice
        logger.critical("fatal_error", error=message, **payload)
        return

    console = get_console()
    if is_plain_output():
        console.print(f"FATAL: {message}", markup=False)
        if detail:
            console.print(f"  detail: {detail}", markup=False)
        if advice:
            console.print(f"  advice: {advice}", markup=False)
        return

    body_lines = [f"[bold red]{escape(message)}[/]"]
    if detail:
        body_lines.append(f"[purple]Detail:[/] {escape(detail)}")
    if advice:
        body_lines.append(f"[cyan]Advice:[/] {escape(advice)}")

    console.print(
        Panel(
            "\n".join(body_lines),
            title="[bold red]FATAL[/]",
            border_style="red",
            padding=(1, 2),
        )
    )


def print_banner() -> str:
    """Draw the opentide icon and tagline, and return them as plain text.

    .. deprecated:: 0.18
        The CLI draws its own marks (``opentide.cli.ui.brand``). This function
        is removed in a later release.
    """
    from opentide.cli.ui import brand

    warnings.warn(
        "print_banner() is deprecated and will be removed in a later release; "
        "the opentide CLI draws its own marks.",
        DeprecationWarning,
        stacklevel=2,
    )
    banner = f"{brand.icon(mono=True).plain}\nopentide · {brand.TAGLINE}"
    console = get_console()
    if is_json_output() or is_plain_output() or not brand.can_draw(console):
        return banner
    mark = brand.icon(mono=brand.is_mono(console))
    console.print(mark)
    console.print(
        Text.assemble(brand.pill(mono=brand.is_mono(console)), " ", (brand.TAGLINE, "italic"))
    )
    return banner
