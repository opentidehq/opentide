"""Logging configuration and structlog initialisation."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog
from rich.console import Console
from rich.logging import RichHandler

from opentide.core.logging.render import OpenTideConsoleRenderer

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

_config: LoggingConfig | None = None
_console = Console(stderr=True, highlight=False)
_stdout_console = Console(highlight=False)


@dataclass(frozen=True)
class LoggingConfig:
    """Runtime logging preferences for a single process."""

    debug: bool = False
    json_output: bool = False
    plain: bool = False

    @classmethod
    def from_env(cls) -> LoggingConfig:
        """Build configuration from standard environment variables."""
        no_color = bool(os.getenv("NO_COLOR")) or os.getenv("FORCE_COLOR") == "0"
        return cls(
            debug=bool(os.getenv("DEBUG_ENABLED")),
            json_output=os.getenv("OPENTIDE_LOG_JSON") == "1",
            plain=no_color,
        )

    @classmethod
    def from_cli_context(cls, ctx: CliContext) -> LoggingConfig:
        """Build configuration from an active CLI context."""
        no_color = bool(os.getenv("NO_COLOR")) or os.getenv("FORCE_COLOR") == "0"
        return cls(
            debug=ctx.debug,
            json_output=ctx.json_output,
            plain=ctx.no_color or no_color,
        )


def current_config() -> LoggingConfig:
    """Return the active logging configuration."""
    return _config or LoggingConfig.from_env()


def is_debug_enabled() -> bool:
    """Return True when verbose debug logging is requested."""
    return current_config().debug


def is_json_output() -> bool:
    """Return True when logs should be emitted as JSON."""
    return current_config().json_output


def is_plain_output() -> bool:
    """Return True when Rich styling should be suppressed."""
    config = current_config()
    return config.plain or config.json_output


def get_console() -> Console:
    """Return the shared Rich console used for presentation output."""
    return _console


def get_stdout_console() -> Console:
    """Return the shared Rich console used for command results."""
    return _stdout_console


def _make_console(*, stderr: bool, config: LoggingConfig) -> Console:
    """Create a stream-aware console without forcing ANSI into redirects."""
    force_color = os.getenv("FORCE_COLOR", "").lower() in {"1", "true", "yes"}
    force_terminal = True if force_color and not config.plain and not config.json_output else None
    return Console(
        stderr=stderr,
        highlight=False,
        no_color=config.plain or config.json_output,
        force_terminal=force_terminal,
    )


def _shared_pre_chain() -> list[Any]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]


def init_logging(config: LoggingConfig | None = None, *, force: bool = False) -> None:
    """Initialise structlog and stdlib logging once per process."""
    global _config, _console, _stdout_console
    if _config is not None and not force:
        return

    _config = config or LoggingConfig.from_env()
    log_level = (
        logging.DEBUG if _config.debug else logging.INFO if _config.json_output else logging.WARNING
    )
    _console = _make_console(stderr=True, config=_config)
    _stdout_console = _make_console(stderr=False, config=_config)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(log_level)

    if _config.json_output:
        import orjson

        def _orjson_serializer(obj: object, **_kwargs: object) -> str:
            return orjson.dumps(obj).decode("utf-8")

        handler: logging.Handler = logging.StreamHandler(sys.stderr)
        formatter = structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=_shared_pre_chain(),
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(serializer=_orjson_serializer),
            ],
        )
    else:
        handler = RichHandler(
            console=_console,
            rich_tracebacks=not _config.plain,
            show_path=_config.debug,
            markup=False,
            show_level=True,
            show_time=False,
        )
        formatter = structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=_shared_pre_chain(),
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                OpenTideConsoleRenderer(use_color=False),
            ],
        )

    handler.setFormatter(formatter)
    handler.setLevel(log_level)
    root.addHandler(handler)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def configure_logging(*, force: bool = False) -> None:
    """Compatibility alias for lazy initialisation."""
    init_logging(force=force)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger, configuring logging on first use."""
    init_logging()
    return structlog.get_logger(name or "opentide")


def bind_context(**kwargs: Any) -> None:
    """Bind key=value pairs to the current structlog context."""
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    """Clear structlog context variables."""
    structlog.contextvars.clear_contextvars()


def reset_for_tests() -> None:
    """Reset module state — test helper only."""
    global _config
    _config = None
