"""Structured logging for OpenTide — structlog processors with Rich console output."""

from opentide.core.logging.compat import LogCategory, log
from opentide.core.logging.config import (
    LoggingConfig,
    bind_context,
    category_level,
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
from opentide.core.logging.console import print_banner

__all__ = [
    "LogCategory",
    "LoggingConfig",
    "bind_context",
    "category_level",
    "clear_context",
    "configure_logging",
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
