"""Objective sections: overview, threats addressed, signals and their rule coverage."""

from __future__ import annotations

from collections.abc import Sequence

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.facts.platforms import platform_label
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.page import Section, join, key_value_table, section
from opentide.documentation.markdown.text import (
    inline_code,
    join_lines,
    plural,
    table_cell,
)
from opentide.documentation.parts.common import Links, technique_links
from opentide.documentation.vocabulary import enrich
from opentide.models.objective import (
    DetectionExample,
    DetectionObjective,
    DetectionSignal,
    ExternalDetector,
)
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector


def implementing_rules(objective: DetectionObjective, catalog: DocumentationCatalog) -> list[str]:
    """Rules implementing the objective itself or one of its signals, in catalogue order."""
    found: set[str] = set()
    for signal in objective.objective.signals:
        found.update(catalog.rules_for_signal(signal.uuid))
    for record in catalog.rules:
        if getattr(record.model, "detection_model", None) == objective.metadata.uuid:
            found.add(record.uuid)
    ordered = [record.uuid for record in catalog.rules if record.uuid in found]
    return ordered + sorted(found - set(ordered))


def overview(objective: DetectionObjective, links: Links) -> str:
    body = objective.objective
    rules = implementing_rules(objective, links.catalog)
    rows = [
        ("Priority", table_cell(body.priority)),
        ("Type", enrich("detection.types", body.type).label),
        ("Composition", enrich("detection.composition", body.composition.strategy).label),
        ("Investment", table_cell(body.investment or "")),
        ("Threats addressed", join_lines(links.to(uuid) for uuid in body.threats or [])),
        ("Signals", plural(len(body.signals), "signal")),
        ("Detection rules", plural(len(rules), "rule")),
        ("Platforms", ", ".join(_platforms(rules, links.catalog))),
        ("ATT&CK", technique_links(body.mitre_attack or [], links.formatter)),
    ]
    return key_value_table(links.formatter, rows, headers=("Property", "Value"))


def composition_body(objective: DetectionObjective, formatter: MarkdownFormatter) -> str:
    composition = objective.objective.composition
    entry = enrich("detection.composition", composition.strategy)
    lead = f"**{entry.label}**"
    if entry.description:
        lead += f": {' '.join(entry.description.split())}"
    return join([formatter.paragraph(lead), formatter.paragraph(composition.description)])


def threats_body(objective: DetectionObjective, links: Links) -> str:
    rows: list[list[str]] = []
    for uuid in objective.objective.threats or []:
        record = links.catalog.resolve_record(uuid)
        threat = record.model if record is not None else None
        if isinstance(threat, ThreatVector):
            criticality = enrich("criticality", threat.criticality).label
            killchain = threat.threat.killchain
            phases = killchain if isinstance(killchain, list) else [killchain] if killchain else []
            rows.append([links.to(uuid), criticality, ", ".join(phases) or "-"])
        else:
            rows.append([links.to(uuid, with_uuid=True), "-", "-"])
    if not rows:
        return ""
    return links.formatter.table(["Threat vector", "Criticality", "Kill chain"], rows)


def signal_sections(objective: DetectionObjective, links: Links) -> list[Section]:
    """One section per signal; its heading is the anchor rule pages link to."""
    return [_signal_section(signal, links) for signal in objective.objective.signals]


def _signal_section(signal: DetectionSignal, links: Links) -> Section:
    formatter = links.formatter
    rules = links.catalog.rules_for_signal(signal.uuid)
    rows = [
        ("Severity", enrich("alert_severity", signal.severity).label),
        ("Methodology", enrich("detection.methodology", signal.methodology).label),
        ("Effort", str(signal.effort) if signal.effort is not None else ""),
        ("Entities", ", ".join(enrich("signal.entities", e).label for e in signal.entities)),
        ("Data availability", table_cell(signal.data.availability)),
        ("Data requirements", table_cell(signal.data.requirements)),
        ("Log sources", ", ".join(inline_code(s) for s in signal.data.logsources or [])),
        ("Implemented by", join_lines(links.to(uuid) for uuid in rules) or "No rule yet"),
        ("UUID", inline_code(signal.uuid)),
    ]
    return section(
        signal.name,
        formatter.paragraph(signal.description),
        key_value_table(formatter, rows, headers=("Property", "Value")),
        _detectors(signal.detectors or [], formatter),
        _examples(signal.examples or [], formatter),
    )


def _detectors(detectors: Sequence[ExternalDetector], formatter: MarkdownFormatter) -> str:
    if not detectors:
        return ""
    rows = [
        [
            table_cell(detector.name),
            table_cell(detector.technology),
            table_cell(detector.description),
            formatter.link("Reference", detector.link) if detector.link else "-",
        ]
        for detector in detectors
    ]
    return join(
        [
            "**Existing detectors**",
            formatter.table(["Detector", "Technology", "Description", "Link"], rows),
        ]
    )


def _examples(examples: Sequence[DetectionExample], formatter: MarkdownFormatter) -> str:
    if not examples:
        return ""
    parts = ["**Examples**"]
    for index, example in enumerate(examples, start=1):
        parts.append(
            f"{index}. {' '.join(example.description.split())} "
            f"({formatter.link('source', example.link)})"
        )
        if example.query:
            parts.append(
                formatter.code_block(example.language or "text", example.query.rstrip("\n"))
            )
    return join(parts)


def coverage_matrix(objective: DetectionObjective, links: Links) -> str:
    """Signals against the rules implementing them and where those rules deploy."""
    if not objective.objective.signals:
        return ""
    rows: list[list[str]] = []
    listed: set[str] = set()
    for signal in objective.objective.signals:
        rules = links.catalog.rules_for_signal(signal.uuid)
        listed.update(rules)
        rows.append(
            [
                table_cell(signal.name),
                join_lines(links.to(uuid) for uuid in rules) or "*None*",
                join_lines(_rule_platforms(uuid, links.catalog) for uuid in rules) or "-",
            ]
        )
    direct = [
        record.uuid
        for record in links.catalog.rules
        if getattr(record.model, "detection_model", None) == objective.metadata.uuid
        and record.uuid not in listed
    ]
    if direct:
        rows.append(
            [
                "*Objective as a whole*",
                join_lines(links.to(uuid) for uuid in direct),
                join_lines(_rule_platforms(uuid, links.catalog) for uuid in direct),
            ]
        )
    return links.formatter.table(["Signal", "Rules", "Platforms and status"], rows)


def _rule_platforms(rule_uuid: str, catalog: DocumentationCatalog) -> str:
    record = catalog.resolve_record(rule_uuid)
    rule = record.model if record is not None else None
    if not isinstance(rule, DetectionRule):
        return "-"
    statuses = rule.platform_statuses
    if not statuses:
        return "-"
    return ", ".join(
        f"{platform_label(platform)} {inline_code(status)}" for platform, status in statuses.items()
    )


def _platforms(rule_uuids: Sequence[str], catalog: DocumentationCatalog) -> list[str]:
    found: dict[str, None] = {}
    for uuid in rule_uuids:
        record = catalog.resolve_record(uuid)
        rule = record.model if record is not None else None
        if isinstance(rule, DetectionRule):
            for platform in rule.platform_statuses:
                found.setdefault(platform_label(platform))
    return sorted(found)
