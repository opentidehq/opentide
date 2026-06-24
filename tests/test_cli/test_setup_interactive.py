"""Tests for shared setup interactive helpers."""

from __future__ import annotations

from opentide.cli.enums import DetectionPlatform, McpHost, SkillTarget
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
