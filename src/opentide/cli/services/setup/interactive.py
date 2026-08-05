"""Shared interactive prompts for setup wizards."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import TypeVar

import questionary
from questionary import Choice, Style

from opentide.cli.enums import DetectionPlatform, McpHost, SkillTarget, platform_label

T = TypeVar("T")

PROMPT_STYLE = Style(
    [
        ("qmark", "fg:#00aaff bold"),
        ("question", "bold"),
        ("answer", "fg:#00aaff bold"),
        ("pointer", "fg:#00aaff bold"),
        ("highlighted", "fg:#00aaff bold"),
        ("selected", "fg:#00aa88"),
        ("instruction", "fg:#888888"),
    ]
)


class InteractiveRequiredError(RuntimeError):
    """Raised when a wizard is started without an interactive terminal."""


def require_interactive() -> None:
    """Fail fast instead of hanging when stdin is not interactive."""
    if not sys.stdin.isatty():
        raise InteractiveRequiredError(
            "Interactive setup requires a terminal. "
            "Use explicit setup flags with --yes for non-interactive execution."
        )


def _answer(value: T | None) -> T:
    if value is None:
        raise KeyboardInterrupt
    return value


def ask_text(message: str, *, default: str = "") -> str:
    """Ask for free text using the shared prompt theme."""
    return _answer(questionary.text(message, default=default, style=PROMPT_STYLE).ask())


def ask_confirm(message: str, *, default: bool = False) -> bool:
    """Ask for an explicit yes/no confirmation."""
    return _answer(questionary.confirm(message, default=default, style=PROMPT_STYLE).ask())


def ask_select(
    message: str,
    choices: Sequence[tuple[str, T]],
    *,
    default: T | None = None,
) -> T:
    """Select one value with arrow keys."""
    entries = [Choice(label, value=value) for label, value in choices]
    return _answer(
        questionary.select(
            message,
            choices=entries,
            default=default,
            style=PROMPT_STYLE,
            use_shortcuts=True,
        ).ask()
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
    validation = (
        (lambda values: bool(values) or "Select at least one option") if require_selection else None
    )
    return _answer(
        questionary.checkbox(
            message,
            choices=entries,
            validate=validation,
            style=PROMPT_STYLE,
        ).ask()
    )


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
