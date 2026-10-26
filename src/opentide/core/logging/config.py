"""Logging configuration and structlog initialisation."""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog
from rich.console import Console
from rich.segment import Segment

from opentide.core.logging.render import ConsoleLogHandler, OpentideConsoleRenderer

if TYPE_CHECKING:
    from opentide.cli.context import CliContext


class EncodingSafeConsole(Console):
    """A console that never raises ``UnicodeEncodeError`` on a narrow stream.

    What it writes goes through :func:`opentide.cli.ui.glyphs.encodable`, so on
    an ASCII stream (``PYTHONIOENCODING=ascii``) ``·`` prints as ``-`` and ``…``
    as ``...``. Text the stream can encode is written unchanged.
    """

    def _render_buffer(self, buffer: Iterable[Segment]) -> str:
        from opentide.cli.ui.glyphs import encodable

        return encodable(super()._render_buffer(buffer), self.file)


_config: LoggingConfig | None = None
_console: Console = EncodingSafeConsole(stderr=True, highlight=False)
_stdout_console: Console = EncodingSafeConsole(highlight=False)


@dataclass(frozen=True)
class LoggingConfig:
    """Runtime logging preferences for a single process."""

    debug: bool = False
    json_output: bool = False
    plain: bool = False
    #: ``--quiet``: errors only.
    quiet: bool = False
    #: Print log lines unwrapped (every mode but ``human``).
    soft_wrap: bool = False
    #: No colour, the rest unchanged: ``plain`` and ``agent`` mode on a terminal.
    no_color: bool = False

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
        from opentide.cli.ui.mode import OutputMode, get_mode

        no_color = bool(os.getenv("NO_COLOR")) or os.getenv("FORCE_COLOR") == "0"
        return cls(
            debug=ctx.debug,
            json_output=ctx.json_output,
            plain=ctx.no_color or no_color,
            quiet=ctx.quiet,
            soft_wrap=get_mode() is not OutputMode.HUMAN,
            no_color=colourless_mode(),
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


#: ``""`` stays off: Rich, and so Typer's help panels, read an empty
#: ``FORCE_COLOR`` as "not a terminal", and log lines should agree with them.
_FORCE_COLOR_OFF = frozenset({"", "0", "false", "no", "off"})


def forced_terminal(variable: str = "FORCE_COLOR") -> bool | None:
    """Whether *variable* forces a terminal; ``None`` leaves it to detection.

    Rich and Typer force a terminal for any non-empty ``FORCE_COLOR``, ``"0"``
    included, and Typer does the same for ``PY_COLORS``, which writes escapes
    into redirected output for a user who asked for less colour. Callers pass
    this as ``force_terminal`` whenever it is set.
    """
    force_color = os.getenv(variable)
    if force_color is None:
        return None
    return force_color.strip().lower() not in _FORCE_COLOR_OFF


def colourless_mode() -> bool:
    """Whether the output mode is ``plain`` or ``agent`` and nothing forces colour.

    Those modes colour only when ``FORCE_COLOR`` or ``PY_COLORS`` asks for it,
    a terminal or not: CI logs and agent transcripts get no escapes.
    """
    from opentide.cli.ui.mode import OutputMode, get_mode

    if get_mode() not in (OutputMode.PLAIN, OutputMode.AGENT):
        return False
    return not (forced_terminal() or forced_terminal("PY_COLORS"))


def _make_console(*, stderr: bool, config: LoggingConfig) -> Console:
    """Create a stream-aware console without forcing ANSI into redirects."""
    plain = config.plain or config.json_output
    forced = forced_terminal()
    return EncodingSafeConsole(
        stderr=stderr,
        highlight=False,
        no_color=plain or config.no_color,
        force_terminal=None if forced is None else forced and not plain,
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


def log_level(config: LoggingConfig) -> int:
    """DEBUG with ``--debug``, ERROR with ``--quiet``, WARNING otherwise (JSON included)."""
    if config.debug:
        return logging.DEBUG
    if config.quiet:
        return logging.ERROR
    return logging.WARNING


def init_logging(config: LoggingConfig | None = None, *, force: bool = False) -> None:
    """Initialise structlog and stdlib logging once per process."""
    global _config, _console, _stdout_console
    if _config is not None and not force:
        return

    _config = config or LoggingConfig.from_env()
    level = log_level(_config)
    _console = _make_console(stderr=True, config=_config)
    _stdout_console = _make_console(stderr=False, config=_config)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

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
        # One label per line: the renderer writes it, the handler only styles it.
        handler = ConsoleLogHandler(_console, soft_wrap=_config.soft_wrap, show_time=_config.debug)
        formatter = structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=_shared_pre_chain(),
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                OpentideConsoleRenderer(use_color=False),
            ],
        )

    handler.setFormatter(formatter)
    handler.setLevel(level)
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
