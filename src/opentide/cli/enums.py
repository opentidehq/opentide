"""CLI enumerations and platform name mapping."""

from __future__ import annotations

from enum import Enum

from opentide.validation.checks.kinds import ValidateCheck


class DetectionPlatform(str, Enum):
    """Detection platform identifiers for CLI flags."""

    sentinel = "sentinel"
    splunk = "splunk"
    crowdstrike = "crowdstrike"
    defender = "defender_for_endpoint"
    sentinel_one = "sentinel_one"
    carbon_black = "carbon_black_cloud"
    harfanglab = "harfanglab"


QUERY_VALIDATION_PLATFORMS: frozenset[str] = frozenset(
    {
        DetectionPlatform.sentinel.value,
        DetectionPlatform.defender.value,
        DetectionPlatform.splunk.value,
        DetectionPlatform.sentinel_one.value,
        DetectionPlatform.carbon_black.value,
    }
)


class GeneratePhase(str, Enum):
    """Generation pipeline phases."""

    object_vocab = "index"
    templates = "templates"
    schemas = "schemas"
    revisions = "revisions"
    snippets = "snippets"
    exports = "exports"
    playbook_map = "playbook-map"


class DocumentScope(str, Enum):
    """Documentation generation scopes."""

    rules = "rules"
    objectives = "objectives"
    threats = "threats"
    index = "index"


class ExportTarget(str, Enum):
    """Export targets."""

    navigator = "navigator"
    table = "table"
    playbook_map = "playbook-map"


class ExtractImport(str, Enum):
    """Platform import targets."""

    sentinel = "sentinel"
    defender = "defender"


class CiPlatform(str, Enum):
    """CI/CD platform choices for setup."""

    github = "github"
    gitlab = "gitlab"
    azure = "azure"
    none = "none"


class McpHost(str, Enum):
    """MCP configuration targets for ``opentide setup mcp``."""

    vscode = "vscode"
    cursor = "cursor"
    claude_code = "claude-code"
    generic = "generic"


class SkillTarget(str, Enum):
    """Agent skill targets for ``opentide setup skills``."""

    cursor = "cursor"
    claude_code = "claude-code"
    generic = "generic"
    github_copilot = "github-copilot"


def platform_label(platform: DetectionPlatform) -> str:
    """Human-readable platform label."""
    labels = {
        DetectionPlatform.sentinel: "Microsoft Sentinel",
        DetectionPlatform.splunk: "Splunk Enterprise Security",
        DetectionPlatform.crowdstrike: "CrowdStrike Falcon",
        DetectionPlatform.defender: "Microsoft Defender for Endpoint",
        DetectionPlatform.sentinel_one: "SentinelOne",
        DetectionPlatform.carbon_black: "Carbon Black Cloud",
        DetectionPlatform.harfanglab: "HarfangLab",
    }
    return labels.get(platform, platform.value)


__all__ = [
    "CiPlatform",
    "DetectionPlatform",
    "DocumentScope",
    "ExportTarget",
    "ExtractImport",
    "GeneratePhase",
    "McpHost",
    "QUERY_VALIDATION_PLATFORMS",
    "SkillTarget",
    "ValidateCheck",
    "platform_label",
]
