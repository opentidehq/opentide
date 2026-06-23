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
    "print_banner",
    "reset_for_tests",
]
