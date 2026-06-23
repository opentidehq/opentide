"""Structured logging for OpenTide — structlog processors with Rich console output."""

from opentide.core.logging.config import (
    LoggingConfig,
    bind_context,
    clear_context,
    configure_logging,
    get_console,
    get_logger,
    init_logging,
    is_debug_enabled,
    is_json_output,
    is_plain_output,
    reset_for_tests,
)
from opentide.core.logging.console import emit_fatal, emit_section, print_banner

_LEVEL_MAP = {
    "TITLE": "info",
    "INFO": "info",
    "DEBUG": "debug",
    "WARNING": "warning",
    "FAILURE": "error",
    "FATAL": "critical",
    "SUCCESS": "info",
    "ONGOING": "info",
    "SKIP": "info",
}


def log(category: str, *args: object) -> None:
    """Backward-compatible shim for legacy ``log(category, ...)`` call sites."""
    level = _LEVEL_MAP.get(category.upper(), "info")
    detail = " | ".join(str(arg) for arg in args) if args else None
    event = category.lower()
    logger = get_logger("opentide")
    if detail:
        getattr(logger, level)(event, detail=detail)
    else:
        getattr(logger, level)(event)


__all__ = [
    "LoggingConfig",
    "bind_context",
    "clear_context",
    "configure_logging",
    "emit_fatal",
    "emit_section",
    "get_console",
    "get_logger",
    "init_logging",
    "is_debug_enabled",
    "is_json_output",
    "is_plain_output",
    "log",
    "print_banner",
    "reset_for_tests",
]
