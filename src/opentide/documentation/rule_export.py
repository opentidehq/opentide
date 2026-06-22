"""Detection rule documentation export — typed OpenTide.Rules access."""

from __future__ import annotations

from opentide.models.rule import DetectionRule


def document_detection_rule(rule: DetectionRule) -> str:
    """Render markdown documentation for a typed detection rule."""
    lines = [
        f"# {rule.name}",
        "",
        rule.description,
        "",
        "## Metadata",
        "",
        f"- **UUID**: `{rule.metadata.uuid}`",
        f"- **Schema**: `{rule.metadata.schema_id}`",
        f"- **Status**: {rule.status}",
        f"- **Severity**: {rule.severity}",
        "",
    ]

    if rule.techniques:
        technique_lines = [f"- {technique}" for technique in rule.techniques]
        lines.extend(["## Techniques", "", *technique_lines, ""])

    if rule.configurations:
        lines.append("## Platform configurations")
        lines.append("")
        for platform_name in (
            "sentinel",
            "defender_for_endpoint",
            "splunk",
            "sentinel_one",
            "crowdstrike",
            "harfanglab",
            "carbon_black_cloud",
        ):
            config = getattr(rule.configurations, platform_name, None)
            if config is None:
                continue
            lines.append(f"### {platform_name}")
            lines.append("")
            if getattr(config, "query", None):
                lines.extend(["```sql", config.query, "```", ""])
            elif getattr(config, "search", None):
                lines.extend(["```spl", config.search, "```", ""])

    return "\n".join(lines).strip() + "\n"
