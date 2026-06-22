"""CLI enumerations and platform name mapping."""

from __future__ import annotations

from enum import Enum


class DetectionPlatform(str, Enum):
    """Detection platform identifiers for CLI flags."""

    sentinel = "sentinel"
    splunk = "splunk"
    crowdstrike = "crowdstrike"
    defender = "defender_for_endpoint"
    sentinel_one = "sentinel_one"
    carbon_black = "carbon_black_cloud"
    harfanglab = "harfanglab"


# Platforms with query syntax validators (5 of 7).
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

    index = "index"
    templates = "templates"
    schemas = "schemas"
    revisions = "revisions"
    snippets = "snippets"
    exports = "exports"
    playbook_map = "playbook-map"


class ValidateCheck(str, Enum):
    """Object validation check types."""

    id_uniqueness = "id-uniqueness"
    uuid_format = "uuid-format"
    schema = "schema"
    cve = "cve"


class DocumentScope(str, Enum):
    """Documentation generation scopes."""

    rules = "rules"
    objectives = "objectives"
    vocabularies = "vocabularies"
    metaschemas = "metaschemas"
    models = "models"
    navigation = "navigation"


class ExportTarget(str, Enum):
    """Export targets."""

    navigator = "navigator"
    table = "table"
    playbook_map = "playbook-map"


class ExtractFramework(str, Enum):
    """External framework extraction targets."""

    attack = "attack"
    d3fend = "d3fend"
    engage = "engage"
    nist = "nist"
    react = "react"


class ExtractImport(str, Enum):
    """Platform import targets."""

    sentinel = "sentinel"
    defender = "defender"


class CiPlatform(str, Enum):
    """CI/CD platform choices for init."""

    github = "github"
    gitlab = "gitlab"
    azure = "azure"
    none = "none"


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
