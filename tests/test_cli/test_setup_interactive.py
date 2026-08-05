"""Tests for shared setup interactive helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from opentide.cli.enums import DetectionPlatform, McpHost, SkillTarget
from opentide.cli.services.setup import interactive
from opentide.cli.services.setup.interactive import (
    MCP_LABELS,
    SKILL_LABELS,
    mcp_hosts_from_keys,
    parse_multi_select,
    parse_platform_tokens,
    skill_targets_from_keys,
)


def test_parse_platform_tokens_aliases() -> None:
    platforms = parse_platform_tokens("sentinel, defender, sentinel-one, carbon-black")
    assert platforms == [
        DetectionPlatform.sentinel,
        DetectionPlatform.defender,
        DetectionPlatform.sentinel_one,
        DetectionPlatform.carbon_black,
    ]


def test_parse_platform_tokens_ignores_unknown() -> None:
    assert parse_platform_tokens("sentinel,not-a-platform") == [DetectionPlatform.sentinel]


def test_parse_multi_select_mcp() -> None:
    keys = parse_multi_select("vscode, cursor, claude-code", MCP_LABELS)
    assert keys == ["vscode", "cursor", "claude-code"]


def test_parse_multi_select_skills() -> None:
    keys = parse_multi_select("generic, github-copilot", SKILL_LABELS)
    assert keys == ["generic", "github-copilot"]


def test_mcp_hosts_from_keys() -> None:
    hosts = mcp_hosts_from_keys(["vscode", "cursor"])
    assert hosts == [McpHost.vscode, McpHost.cursor]


def test_skill_targets_from_keys() -> None:
    targets = skill_targets_from_keys(["generic", "claude-code"])
    assert targets == [SkillTarget.generic, SkillTarget.claude_code]


def test_require_interactive_rejects_redirected_stdin(monkeypatch) -> None:
    monkeypatch.setattr(interactive.sys.stdin, "isatty", lambda: False)
    with pytest.raises(interactive.InteractiveRequiredError, match="requires a terminal"):
        interactive.require_interactive()


def test_questionary_prompt_helpers(monkeypatch) -> None:
    prompt = MagicMock()
    prompt.ask.side_effect = ["text", True, "choice", ["one"]]
    monkeypatch.setattr(interactive.questionary, "text", lambda *args, **kwargs: prompt)
    monkeypatch.setattr(interactive.questionary, "confirm", lambda *args, **kwargs: prompt)
    monkeypatch.setattr(interactive.questionary, "select", lambda *args, **kwargs: prompt)
    monkeypatch.setattr(interactive.questionary, "checkbox", lambda *args, **kwargs: prompt)

    assert interactive.ask_text("Text") == "text"
    assert interactive.ask_confirm("Confirm") is True
    assert interactive.ask_select("Select", [("Choice", "choice")]) == "choice"
    assert interactive.ask_checkbox("Checkbox", [("One", "one")]) == ["one"]


def test_ask_platforms_uses_friendly_checkbox(monkeypatch) -> None:
    monkeypatch.setattr(
        interactive,
        "ask_checkbox",
        lambda *args, **kwargs: [DetectionPlatform.sentinel],
    )
    assert interactive.ask_platforms() == [DetectionPlatform.sentinel]


def test_prompt_cancel_raises_keyboard_interrupt(monkeypatch) -> None:
    prompt = MagicMock()
    prompt.ask.return_value = None
    monkeypatch.setattr(interactive.questionary, "text", lambda *args, **kwargs: prompt)
    with pytest.raises(KeyboardInterrupt):
        interactive.ask_text("Text")
