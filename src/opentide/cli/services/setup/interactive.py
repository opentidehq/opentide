"""Shared interactive prompts for setup wizards."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

import questionary
from prompt_toolkit.filters import to_filter
from questionary import Choice, Question, Style

from opentide.cli.enums import DetectionPlatform, McpHost, SkillTarget, platform_label

T = TypeVar("T")

#: The wizard in the brand: the question mark is a Reflex Blue square with the
#: white wave, answers and the pointer are bold in the terminal's own colour
#: (blue is a fill, never a text colour), and a refused answer shows on a
#: toolbar that cannot be missed. questionary merges its own style underneath
#: (an amber answer); ``noinherit`` drops it, so no yellow reaches the screen.
QMARK = "≋"
PROMPT_STYLE = Style(
    [
        ("qmark", "fg:#ffffff bg:#001489 bold"),
        ("question", "bold"),
        ("answer", "noinherit bold"),
        ("pointer", "bold"),
        ("highlighted", "bold"),
        ("selected", "bold"),
        ("separator", "fg:#8b949e"),
        ("instruction", "fg:#8b949e"),
        ("text", ""),
        ("disabled", "fg:#8b949e italic"),
        ("validation-toolbar", "fg:#ffffff bg:#a40e26 bold"),
    ]
)


class InteractiveRequiredError(RuntimeError):
    """Raised when a wizard is started without an interactive terminal."""


def require_interactive() -> None:
    """Fail fast instead of hanging when stdin is not interactive.

    A coding agent never gets a prompt, even on a TTY: it cannot answer one.
    The message says why; the command that caught it adds the flags that
    answer the prompt, which only it knows.
    """
    from opentide.cli.ui.mode import OutputMode, detect_agent, get_mode

    if get_mode() is OutputMode.AGENT:
        agent = detect_agent()
        reader = f"a coding agent ({agent})" if agent else "agent output mode"
        raise InteractiveRequiredError(f"Interactive setup does not prompt in {reader}.")
    if not sys.stdin.isatty():
        raise InteractiveRequiredError("Interactive setup requires a terminal.")


def _answer(value: T | None) -> T:
    if value is None:
        raise KeyboardInterrupt
    return value


def _ask(question: Question) -> Any:
    """Ask *question*; a refused answer's message shows on the row below it.

    prompt_toolkit lets the answer row grow into every row below the cursor,
    which put the validation toolbar at the bottom of the terminal, a dozen
    rows from the field. ``unsafe_ask`` lets Ctrl-C reach the CLI, which
    prints the one ``interrupted`` line; ``ask`` would print questionary's
    "Cancelled by user" first.
    """
    for window in question.application.layout.find_all_windows():
        window.dont_extend_height = to_filter(True)
    return _answer(question.unsafe_ask())


def require_text(what: str) -> Callable[[str], bool | str]:
    """A validator that refuses an empty answer, naming what is missing."""

    def validate(value: str) -> bool | str:
        return bool(value.strip()) or f"Enter {what}; the field cannot be empty"

    return validate


def ask_text(
    message: str,
    *,
    default: str = "",
    validate: Callable[[str], bool | str] | None = None,
) -> str:
    """Ask for free text using the shared prompt theme; *validate* refuses an answer visibly."""
    extra: dict[str, Any] = {} if validate is None else {"validate": validate}
    return _ask(
        questionary.text(message, default=default, style=PROMPT_STYLE, qmark=QMARK, **extra)
    )


def ask_confirm(message: str, *, default: bool = False) -> bool:
    """Ask for an explicit yes/no confirmation."""
    return _ask(questionary.confirm(message, default=default, style=PROMPT_STYLE, qmark=QMARK))


def ask_select(
    message: str,
    choices: Sequence[tuple[str, T]],
    *,
    default: T | None = None,
) -> T:
    """Select one value with arrow keys."""
    entries = [Choice(label, value=value) for label, value in choices]
    # questionary types `default` as a str or a Choice; the entry holding the
    # value selects the same item.
    preselected = next((entry for entry in entries if entry.value == default), None)
    if default is not None and preselected is None:
        raise ValueError(f"Default {default!r} is not one of the choices")
    return _ask(
        questionary.select(
            message,
            choices=entries,
            default=preselected,
            style=PROMPT_STYLE,
            qmark=QMARK,
            use_shortcuts=True,
        )
    )


def ask_checkbox(
    message: str,
    choices: Sequence[tuple[str, T]],
    *,
    defaults: Sequence[T] = (),
    require_selection: bool = False,
) -> list[T]:
    """Select zero or more values with a checkbox menu."""
    selected = set(defaults)
    entries = [Choice(label, value=value, checked=value in selected) for label, value in choices]
    prompt_kwargs: dict[str, Any] = {
        "choices": entries,
        "style": PROMPT_STYLE,
        "qmark": QMARK,
    }
    if require_selection:
        prompt_kwargs["validate"] = lambda values: bool(values) or "Select at least one option"
    return _ask(questionary.checkbox(message, **prompt_kwargs))


def ask_platforms(*, require_selection: bool = True) -> list[DetectionPlatform]:
    """Select detection platforms by friendly name."""
    choices = [(platform_label(platform), platform) for platform in DetectionPlatform]
    return ask_checkbox(
        "Detection platforms",
        choices,
        require_selection=require_selection,
    )


def parse_platform_tokens(raw: str) -> list[DetectionPlatform]:
    platforms: list[DetectionPlatform] = []
    for token in raw.split(","):
        token = token.strip().replace("-", "_")
        if token == "sentinel_one":
            platforms.append(DetectionPlatform.sentinel_one)
        elif token == "carbon_black":
            platforms.append(DetectionPlatform.carbon_black)
        elif token == "defender":
            platforms.append(DetectionPlatform.defender)
        elif token:
            try:
                platforms.append(DetectionPlatform(token))
            except ValueError:
                continue
    return platforms


def parse_multi_select(raw: str, choices: dict[str, str]) -> list[str]:
    """Parse comma-separated keys against a label map."""
    selected: list[str] = []
    for token in raw.split(","):
        key = token.strip().lower().replace("_", "-")
        if key in choices:
            selected.append(key)
    return selected


MCP_LABELS = {
    "vscode": "VS Code",
    "cursor": "Cursor",
    "claude-code": "Claude Code",
    "generic": "Generic (opentide.mcp.json)",
}

SKILL_LABELS = {
    "cursor": "Cursor",
    "claude-code": "Claude Code",
    "generic": "Generic (AGENTS.md)",
    "github-copilot": "GitHub Copilot",
}


def mcp_hosts_from_keys(keys: list[str]) -> list[McpHost]:
    return [McpHost(key) for key in keys]


def skill_targets_from_keys(keys: list[str]) -> list[SkillTarget]:
    return [SkillTarget(key) for key in keys]
