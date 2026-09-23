"""Rich presentation helpers for section headers and fatal errors."""

from __future__ import annotations

from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from opentide.core.logging.config import get_console, get_logger, is_json_output, is_plain_output


def emit_section(title: str) -> None:
    """Render a section header."""
    if is_json_output():
        get_logger("opentide").info("section_started", section=title)
        return

    console = get_console()
    if is_plain_output():
        console.print(f"\n== {title} ==\n", markup=False)
        return

    console.rule(f"[bold cyan]{escape(title)}[/]")


def emit_fatal(message: str, *, detail: str = "", advice: str = "") -> None:
    """Render a fatal error panel."""
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
    """Return the OpenTide ASCII banner, rendering it when appropriate."""
    banner = """\
            :--==-:.
         -+*###*####*+:
       -=:   .:  =-*##*.
     -=.  .:.     .+.*=:+
  .-+:  .-:  :  .-- :  .
+*#+   -=.  -:  : :=              The engine powering OpenTIDE Instances
#*-  .==.  :=  .-  +            Part of the OpenThreat Informed Detection Engineering Initiative
:   :==:   =-  .=. .+
   :==-   :=-   --  .+:
  :===.   ==-   :=-   :=-
 .====    ===.   -=-."""

    if is_json_output() or is_plain_output():
        return banner

    get_console().print(
        Panel(
            Text(banner, style="bold blue"),
            title="[bold yellow]Open[/][bold blue]Tide[/]",
            subtitle="[italic]DetectionOps Engine[/]",
            border_style="blue",
            padding=(0, 1),
        )
    )
    return banner
