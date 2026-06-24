"""Shared Rich prompts for setup wizards."""

from __future__ import annotations

from opentide.cli.enums import DetectionPlatform, McpHost, SkillTarget


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
