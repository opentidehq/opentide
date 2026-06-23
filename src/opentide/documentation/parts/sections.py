"""Reusable documentation sections."""

from __future__ import annotations

from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.models.metadata import ObjectMetadata
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector


def render_metadata(metadata: ObjectMetadata, formatter: MarkdownFormatter) -> str:
    lines = [
        formatter.heading(2, "Metadata"),
        f"- **UUID**: `{metadata.uuid}`",
        f"- **Schema**: `{metadata.schema_id}`",
    ]
    if metadata.tlp:
        lines.append(f"- **TLP**: {metadata.tlp}")
    return "\n".join(lines) + "\n"


def render_description(text: str, formatter: MarkdownFormatter) -> str:
    return formatter.heading(2, "Description") + formatter.paragraph(text)


def render_techniques(techniques: list[str], formatter: MarkdownFormatter) -> str:
    if not techniques:
        return ""
    items = "\n".join(f"- {item}" for item in techniques)
    return formatter.heading(2, "Techniques") + items + "\n"


def render_rule_queries(rule: DetectionRule, formatter: MarkdownFormatter) -> str:
    if rule.configurations is None:
        return ""
    chunks: list[str] = [formatter.heading(2, "Platform configurations")]
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
        query = getattr(config, "query", None) or getattr(config, "search", None)
        if not query:
            continue
        lang = "sql" if getattr(config, "query", None) else "spl"
        body = formatter.code_block(lang, query)
        chunks.append(formatter.fold(platform_name, body))
    return "".join(chunks)


def render_signals(objective: DetectionObjective, formatter: MarkdownFormatter) -> str:
    chunks: list[str] = []
    for signal in objective.objective.signals:
        chunks.append(formatter.heading(3, signal.name))
        chunks.append(formatter.paragraph(signal.description))
        if signal.methodology:
            chunks.append(formatter.paragraph(f"**Methodology**: {signal.methodology}"))
    return "".join(chunks)


def render_threat_body(threat: ThreatVector, formatter: MarkdownFormatter) -> str:
    body = threat.threat
    chunks = [render_description(body.description, formatter)]
    if body.att_ck:
        chunks.append(render_techniques(body.att_ck, formatter))
    return "".join(chunks)
