"""Structured logging for OpenTide — structlog processors with Rich console output."""

from __future__ import annotations

import logging
import os
from typing import Any, Literal

import structlog
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.text import Text

LogCategory = Literal[
    "ONGOING",
    "SUCCESS",
    "WARNING",
    "INFO",
    "FAILURE",
    "FATAL",
    "DEBUG",
    "SKIP",
    "TITLE",
]

_CATEGORY_STYLE: dict[str, str] = {
    "ONGOING": "yellow",
    "SUCCESS": "green",
    "WARNING": "yellow",
    "INFO": "blue",
    "FAILURE": "red",
    "FATAL": "bold red",
    "DEBUG": "magenta",
    "SKIP": "cyan",
    "TITLE": "bold magenta",
}

_CATEGORY_LEVEL: dict[str, int] = {
    "ONGOING": logging.INFO,
    "SUCCESS": logging.INFO,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "FAILURE": logging.ERROR,
    "FATAL": logging.CRITICAL,
    "DEBUG": logging.DEBUG,
    "SKIP": logging.INFO,
    "TITLE": logging.INFO,
}

_configured = False
_console = Console(stderr=True)


def is_debug_enabled() -> bool:
    """Return True when verbose debug logging is requested."""
    return bool(os.getenv("DEBUG_ENABLED"))


def is_plain_output() -> bool:
    """Strip Rich markup when VS Code or debug mode needs plain text."""
    return is_debug_enabled() or os.environ.get("TERM_PROGRAM") == "vscode"


def configure_logging(*, force: bool = False) -> None:
    """Initialise structlog and stdlib logging with a Rich console handler."""
    global _configured
    if _configured and not force:
        return

    log_level = logging.DEBUG if is_debug_enabled() else logging.INFO
    use_color = not is_plain_output()

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(log_level)

    handler = RichHandler(
        console=_console,
        rich_tracebacks=use_color,
        show_path=False,
        markup=use_color,
        show_level=True,
        show_time=True,
    )
    handler.setLevel(log_level)

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
        ],
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(colors=use_color),
        ],
    )
    handler.setFormatter(formatter)
    root.addHandler(handler)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    _configured = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger, configuring logging on first use."""
    configure_logging()
    return structlog.get_logger(name or "opentide")


def bind_context(**kwargs: Any) -> None:
    """Bind key=value pairs to the current structlog context (trace spans, job ids)."""
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    """Clear structlog context variables."""
    structlog.contextvars.clear_contextvars()


def log(
    category: LogCategory,
    message: str,
    highlight: str = "",
    advice: str = "",
    icon: str = "",
) -> None:
    """Emit a structured log event with legacy Tide category semantics."""
    if category == "DEBUG" and not is_debug_enabled():
        return

    configure_logging()
    level = _CATEGORY_LEVEL.get(category, logging.INFO)

    if category == "TITLE":
        title = Text(message, justify="center")
        _console.print(
            Panel(title, title="OpenTide", border_style="magenta", padding=(0, 2))
        )
        return

    if category == "FATAL":
        body_lines = [f"[bold red]{message}[/]"]
        if highlight:
            body_lines.append(f"[purple]Detail:[/] {highlight}")
        if advice:
            body_lines.append(f"[cyan]Advice:[/] {advice}")
        _console.print(
            Panel(
                "\n".join(body_lines),
                title="FATAL ERROR",
                border_style="red",
                padding=(1, 2),
            )
        )
        return

    logger = get_logger("opentide")
    event_kwargs: dict[str, Any] = {"category": category}
    if highlight:
        event_kwargs["detail"] = highlight
    if advice:
        event_kwargs["advice"] = advice
    if icon:
        event_kwargs["icon"] = icon

    logger.log(level, message, **event_kwargs)


def print_banner() -> str:
    """Return the OpenTide ASCII banner (Rich-rendered when not plain)."""
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

    if is_plain_output():
        return banner

    _console.print(
        Panel(
            Text(banner, style="bold blue"),
            title="[bold yellow]Open[/][bold blue]Tide[/]",
            subtitle="[italic]Powered by CoreTIDE[/]",
            border_style="blue",
            padding=(0, 1),
        )
    )
    return banner


# Legacy alias retained for rename scripts and external callers.
coretide_intro = print_banner
