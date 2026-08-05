"""Human-readable structlog renderers backed by Rich."""

from __future__ import annotations

from io import StringIO
from typing import Any

from rich.console import Console
from rich.text import Text

_LEVEL_STYLE: dict[str, str] = {
    "DEBUG": "dim magenta",
    "INFO": "blue",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold red",
}


class OpenTideConsoleRenderer:
    """Render structured events into Rich-formatted console lines."""

    def __init__(self, *, use_color: bool = True) -> None:
        self._use_color = use_color

    def __call__(self, _logger: Any, method_name: str, event_dict: dict[str, Any]) -> str:
        return self.render(event_dict, method_name)

    def render(self, event_dict: dict[str, Any], method_name: str) -> str:
        event = event_dict.pop("event", "")
        level = str(event_dict.pop("level", method_name)).upper()
        timestamp = event_dict.pop("timestamp", "")

        for key in ("logger", "exc_info", "stack_info", "category"):
            event_dict.pop(key, None)

        line = Text()
        if timestamp:
            line.append(timestamp, style="dim")
            line.append("  ")

        level_style = _LEVEL_STYLE.get(level, "bold")
        line.append(f"{level:<8}", style=level_style if self._use_color else "")

        line.append("  ")
        label = str(event).replace("_", " ").strip()
        line.append(label[:1].upper() + label[1:])

        for key, value in event_dict.items():
            line.append("\n")
            line.append("           ", style="dim")
            line.append(f"{key}: ", style="dim italic")
            line.append(str(value))

        buffer = StringIO()
        Console(
            file=buffer,
            force_terminal=None,
            color_system=None,
            no_color=True,
            highlight=False,
        ).print(line, end="")
        return buffer.getvalue().rstrip("\n")
