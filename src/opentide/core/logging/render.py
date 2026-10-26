"""Human-readable log lines: one level label, readable text, then the event's fields.

``warning: Tenant targets failed · system: sentinel · detail: timed out``

Log lines carry no timestamp of their own; :class:`ConsoleLogHandler` adds the
time in ``--debug`` runs, where timing is what the reader is after.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import MutableMapping
from typing import Any

from rich.console import Console
from rich.text import Text

#: Severity words, as the CLI prints them (``docs/internal/cli-experience.md``).
_LEVEL_LABEL: dict[str, str] = {
    "DEBUG": "debug",
    "INFO": "info",
    "WARNING": "warning",
    "ERROR": "error",
    "CRITICAL": "error",
}

LEVEL_STYLE: dict[str, str] = {
    "debug": "dim magenta",
    "info": "blue",
    "warning": "bold yellow",
    "error": "bold red",
}

#: An event name rather than prose: ``tenant_targets_failed``, ``share.completed``.
_SLUG = re.compile(r"^[a-z0-9]+(?:[._][a-z0-9]+)*$")


def readable_event(event: object) -> str:
    """``tenant_targets_failed`` → ``Tenant targets failed``; prose is left as written."""
    text = str(event).strip()
    if _SLUG.fullmatch(text):
        text = re.sub(r"[._]", " ", text)
        return text[:1].upper() + text[1:]
    return text


class OpentideConsoleRenderer:
    """Render a structlog event dict into one log line (plus a traceback, if any)."""

    def __init__(self, *, use_color: bool = True) -> None:
        # Colour is applied by ConsoleLogHandler on the level label; the rendered
        # string is plain so it never forces ANSI escapes into a redirect.
        self._use_color = use_color

    def __call__(self, _logger: Any, method_name: str, event_dict: MutableMapping[str, Any]) -> str:
        return self.render(event_dict, method_name)

    def render(self, event_dict: MutableMapping[str, Any], method_name: str) -> str:
        event = event_dict.pop("event", "")
        level = str(event_dict.pop("level", method_name)).upper()
        exception = event_dict.pop("exception", None)
        for key in ("timestamp", "logger", "exc_info", "stack_info", "category"):
            event_dict.pop(key, None)

        parts = [f"{_LEVEL_LABEL.get(level, level.lower())}: {readable_event(event)}"]
        parts.extend(f"{key}: {value}" for key, value in event_dict.items())
        line = " · ".join(parts)
        if exception:
            line = f"{line}\n{exception}"
        return line


class ConsoleLogHandler(logging.Handler):
    """Write formatted log lines to a Rich console, styling only the level label."""

    def __init__(self, console: Console, *, soft_wrap: bool, show_time: bool) -> None:
        super().__init__()
        self.console = console
        self.soft_wrap = soft_wrap
        self.show_time = show_time

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            label, separator, rest = message.partition(": ")
            line = Text()
            if self.show_time:
                stamp = time.strftime("%H:%M:%S", time.localtime(record.created))
                line.append(f"{stamp} ", style="dim")
            if separator and label in LEVEL_STYLE:
                line.append(label + separator, style=LEVEL_STYLE[label])
                line.append(rest)
            else:
                line.append(message)
            self.console.print(line, soft_wrap=self.soft_wrap, highlight=False)
        except Exception:  # noqa: BLE001 - logging must never raise into the caller
            self.handleError(record)
