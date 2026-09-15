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


def _construct_and_stub_ask(monkeypatch, prompt_name: str, result):
    """Build the real Questionary prompt, then stub ``.ask()`` (issue #177)."""
    real = getattr(interactive.questionary, prompt_name)
    mock_ask = MagicMock(return_value=result)

    def wrap(*args, **kwargs):
        assert kwargs.get("validate") is not None or "validate" not in kwargs
        built = real(*args, **kwargs)
        built.ask = mock_ask
        return built

    monkeypatch.setattr(interactive.questionary, prompt_name, wrap)
    return mock_ask


def test_questionary_prompt_helpers_construct_real_prompts(monkeypatch) -> None:
    _construct_and_stub_ask(monkeypatch, "text", "text")
    _construct_and_stub_ask(monkeypatch, "confirm", True)
    _construct_and_stub_ask(monkeypatch, "select", "choice")
    _construct_and_stub_ask(monkeypatch, "checkbox", ["one"])

    assert interactive.ask_text("Text") == "text"
    assert interactive.ask_confirm("Confirm") is True
    assert interactive.ask_select("Select", [("Choice", "choice")]) == "choice"
    assert interactive.ask_checkbox("Checkbox", [("One", "one")]) == ["one"]


def test_ask_checkbox_optional_builds_questionary_prompt(monkeypatch) -> None:
    """questionary.checkbox rejects validate=None (issue #177)."""
    _construct_and_stub_ask(monkeypatch, "checkbox", ["staging"])
    assert interactive.ask_checkbox(
        "CI workflow features",
        [("Staging deployments on pull requests", "staging")],
        defaults=("staging",),
    ) == ["staging"]


def test_ask_checkbox_required_constructs_with_callable_validator(monkeypatch) -> None:
    captured: dict[str, object] = {}
    real_checkbox = interactive.questionary.checkbox
    mock_ask = MagicMock(return_value=["one"])

    def wrap(*args, **kwargs):
        captured.update(kwargs)
        built = real_checkbox(*args, **kwargs)
        built.ask = mock_ask
        return built

    monkeypatch.setattr(interactive.questionary, "checkbox", wrap)
    assert interactive.ask_checkbox(
        "Required",
        [("One", "one")],
        require_selection=True,
    ) == ["one"]
    assert callable(captured.get("validate"))
    validate = captured["validate"]
    assert validate([]) == "Select at least one option"
    assert validate(["one"]) is True


def test_ask_platforms_constructs_required_checkbox(monkeypatch) -> None:
    _construct_and_stub_ask(monkeypatch, "checkbox", [DetectionPlatform.sentinel])
    assert interactive.ask_platforms() == [DetectionPlatform.sentinel]


def test_prompt_cancel_raises_keyboard_interrupt(monkeypatch) -> None:
    _construct_and_stub_ask(monkeypatch, "text", None)
    with pytest.raises(KeyboardInterrupt):
        interactive.ask_text("Text")
