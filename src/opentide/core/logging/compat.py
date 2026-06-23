"""Legacy Tide category logging — thin shim over structlog."""

from __future__ import annotations

from typing import Literal

from opentide.core.logging.config import category_level, get_logger, init_logging, is_debug_enabled
from opentide.core.logging.console import emit_fatal, emit_section

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


def log(
    category: LogCategory,
    message: str,
    highlight: str = "",
    advice: str = "",
) -> None:
    """Emit a structured log event with legacy Tide category semantics."""
    if category == "DEBUG" and not is_debug_enabled():
        return

    init_logging()

    if category == "TITLE":
        emit_section(message)
        return

    if category == "FATAL":
        emit_fatal(message, detail=highlight, advice=advice)
        return

    level = category_level(category)
    event_kwargs: dict[str, str] = {"category": category}
    if highlight:
        event_kwargs["detail"] = highlight
    if advice:
        event_kwargs["advice"] = advice

    get_logger("opentide").log(level, message, **event_kwargs)
