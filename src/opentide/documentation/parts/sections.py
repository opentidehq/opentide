"""Reusable documentation sections."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Literal, cast

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.links import object_link
from opentide.documentation.vocabulary import enrich, enrich_technique
from opentide.generation import framework as fw
from opentide.models.metadata import ObjectMetadata, ObjectReferences
from opentide.models.objective import (
    DetectionExample,
    DetectionObjective,
    DetectionSignal,
    ExternalDetector,
)
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatBody, ThreatVector


def render_metadata(metadata: ObjectMetadata, formatter: MarkdownFormatter) -> str:
    tlp_entry = enrich("tlp", metadata.tlp)
    tlp_id = tlp_entry.raw.get("id") if isinstance(tlp_entry.raw, dict) else ""
    tlp_value = tlp_entry.label
    if isinstance(tlp_id, str) and tlp_id and tlp_id != tlp_value:
        tlp_value = f"{tlp_value} (`{tlp_id}`)"

    rows = [
        ["UUID", f"`{metadata.uuid}`"],
        ["Schema", f"`{metadata.schema_id}`"],
        ["Version", f"`{metadata.version}`"],
        ["Created", f"`{metadata.created}`"],
        ["Modified", f"`{metadata.modified}`"],
        ["TLP", tlp_value],
    ]
    if metadata.author:
        rows.append(["Author", metadata.author])
    if metadata.contributors:
        rows.append(["Contributors", ", ".join(metadata.contributors)])
    if metadata.organisation:
        rows.append(
            ["Organisation", f"{metadata.organisation.name} (`{metadata.organisation.uuid}`)"]
        )
    return formatter.heading(2, "Metadata") + formatter.table(["Field", "Value"], rows)


def render_references(references: ObjectReferences | None, formatter: MarkdownFormatter) -> str:
    if not references:
        return ""

    chunks: list[str] = []
    if references.public:
        chunks.append(formatter.heading(3, "Public"))
        for key, value in sorted(references.public.items()):
            chunks.append(f"- **{key}**: {_render_reference_value(value, formatter)}\n")
    if references.internal:
        chunks.append(formatter.heading(3, "Internal"))
        for key, value in sorted(references.internal.items()):
            chunks.append(f"- **{key}**: {_render_reference_value(value, formatter)}\n")
    if references.reports:
        chunks.append(formatter.heading(3, "Reports"))
        for value in references.reports:
            chunks.append(f"- {_render_reference_value(value, formatter)}\n")

    if not chunks:
        return ""
    return formatter.heading(2, "References") + "".join(chunks)


def render_description(text: str, formatter: MarkdownFormatter) -> str:
    return formatter.heading(2, "Description") + formatter.paragraph(text)


def render_techniques(techniques: list[str], formatter: MarkdownFormatter) -> str:
    if not techniques:
        return ""
    return render_attack_techniques(techniques, formatter)


def render_rule_status(rule: DetectionRule, formatter: MarkdownFormatter) -> str:
    rows = [
        ["Status", f"`{rule.status}`"],
        ["Severity", f"`{rule.severity}`"],
    ]
    return formatter.heading(2, "Status") + formatter.table(["Field", "Value"], rows)


def render_detection_model_link(
    rule: DetectionRule,
    formatter: MarkdownFormatter,
    catalog: DocumentationCatalog,
    *,
    from_folder: str = "Rules",
    uuid_permalinks: bool = False,
    wiki_links: bool = False,
) -> str:
    if not rule.detection_model:
        return ""
    objective = object_link(
        formatter,
        catalog,
        rule.detection_model,
        from_folder=from_folder,
        uuid_permalinks=uuid_permalinks,
        wiki=wiki_links,
    )
    return formatter.heading(2, "Detection model") + f"- **Objective**: {objective}\n"


def render_rule_response(rule: DetectionRule, formatter: MarkdownFormatter) -> str:
    if rule.response is None:
        return ""

    response = rule.response
    chunks: list[str] = [
        formatter.heading(2, "Response"),
        f"- **Alert severity**: {_render_vocab_label('alert_severity', response.alert_severity)}",
    ]
    if response.playbook:
        chunks.append(f"- **Playbook**: {response.playbook}")
    if response.responders:
        chunks.append(f"- **Responders**: {_render_vocab_label('responders', response.responders)}")
    if response.procedure:
        chunks.append(formatter.heading(3, "Procedure").strip())
        chunks.append(f"- **Analysis**: {response.procedure.analysis}")
        if response.procedure.containment:
            chunks.append(f"- **Containment**: {response.procedure.containment}")
        if response.procedure.searches:
            chunks.append(formatter.heading(4, "Searches").strip())
            for search in response.procedure.searches:
                chunks.append(f"- **{search.purpose}** ({search.system})")
                chunks.append(formatter.code_block("text", search.query).strip())
    return "\n".join(chunks) + "\n"


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
        details: list[str] = [
            f"- **Enabled**: `{config.enabled}`",
        ]
        if getattr(config, "status", None):
            details.append(f"- **Status**: `{config.status}`")
        alert_title = _platform_alert_title(config)
        if alert_title:
            details.append(f"- **Alert title**: {alert_title}")
        for mapping in _platform_entity_mappings(config):
            details.append(f"- **Entity mapping**: {mapping}")

        query = _platform_query(config)
        if query:
            details.append("")
            lang = "sql" if getattr(config, "query", None) else "spl"
            details.append(formatter.code_block(lang, query).strip())

        body = "\n".join(details) + "\n"
        chunks.append(formatter.fold(platform_name, body))
    if len(chunks) == 1:
        return ""
    return "".join(chunks)


def render_signals(objective: DetectionObjective, formatter: MarkdownFormatter) -> str:
    if not objective.objective.signals:
        return ""
    chunks: list[str] = [formatter.heading(2, "Signals")]
    for signal in objective.objective.signals:
        chunks.append(formatter.heading(3, signal.name))
        chunks.append(formatter.paragraph(signal.description))
        chunks.extend(_render_signal_meta(signal))
        chunks.append(_render_signal_data(signal, formatter))
        chunks.append(_render_signal_entities(signal))
        if signal.detectors:
            chunks.append(_render_signal_detectors(signal.detectors, formatter))
        if signal.examples:
            chunks.append(_render_signal_examples(signal.examples, formatter))
    return "".join(chunks)


def render_objective_meta(objective: DetectionObjective, formatter: MarkdownFormatter) -> str:
    body = objective.objective
    composition = body.composition or objective.composition
    priority = enrich("criticality", body.priority).label
    objective_type = enrich("detection.types", body.type).label
    composition_label = enrich("detection.composition", composition.strategy).label

    chunks = [formatter.heading(2, "Objective metadata")]
    chunks.append(f"- **Priority**: {priority}")
    chunks.append(f"- **Type**: {objective_type}")
    if body.investment:
        chunks.append(f"- **Investment**: {body.investment}")
    chunks.append(f"- **Composition**: {composition_label}")
    chunks.append(f"- **Composition rationale**: {composition.description}")
    return "\n".join(chunks) + "\n"


def render_signal_mdr_coverage(
    objective: DetectionObjective,
    formatter: MarkdownFormatter,
    catalog: DocumentationCatalog,
    *,
    from_folder: str = "Objectives",
    uuid_permalinks: bool = False,
    wiki_links: bool = False,
    resolve_name: Callable[[str], str] | None = None,
) -> str:
    if not objective.objective.signals:
        return ""
    rows: list[list[str]] = []
    for signal in objective.objective.signals:
        related_rules = catalog.rules_for_signal(signal.uuid)
        if not isinstance(related_rules, list) or not related_rules:
            rows.append([signal.name, "_None_"])
            continue
        display = [
            _rule_coverage_label(
                rule_uuid,
                formatter,
                catalog,
                from_folder=from_folder,
                uuid_permalinks=uuid_permalinks,
                wiki_links=wiki_links,
                resolve_name=resolve_name,
            )
            for rule_uuid in related_rules
        ]
        rows.append([signal.name, "<br>".join(display)])

    return (
        formatter.heading(2, "Signal MDR coverage")
        + formatter.table(headers=["Signal", "Downstream MDR rules"], rows=rows)
    )


def render_related_objects(
    catalog: DocumentationCatalog,
    uuid: str,
    formatter: MarkdownFormatter,
    *,
    from_folder: str,
    direction: str = "both",
    uuid_permalinks: bool = False,
    wiki_links: bool = False,
) -> str:
    """Backlink table for related objects. GitHub cannot click Mermaid nodes."""
    walk = cast(
        Literal["upstream", "downstream", "both"],
        direction if direction in {"upstream", "downstream", "both"} else "both",
    )
    entries = catalog.related_entries(uuid, direction=walk)
    if not isinstance(entries, list) or not entries:
        return ""
    rows: list[list[str]] = []
    for entry in entries:
        object_type = (entry.object_type or "object").title()
        name = object_link(
            formatter,
            catalog,
            entry.uuid,
            from_folder=from_folder,
            uuid_permalinks=uuid_permalinks,
            wiki=wiki_links,
        )
        rows.append(
            [
                object_type,
                name,
                (entry.direction or "-").title(),
                entry.relation or "-",
            ]
        )
    return formatter.heading(2, "Related objects") + formatter.table(
        ["Type", "Name", "Direction", "Relation"],
        rows,
    )


def render_threat_body(threat: ThreatVector, formatter: MarkdownFormatter) -> str:
    body = threat.threat
    chunks = [
        render_description(body.description, formatter),
        render_criticality(threat, formatter),
        render_terrain(body, formatter),
        render_surface(body, formatter),
        render_threat_assessment(body, formatter),
        render_actors(body, formatter),
    ]
    if body.att_ck:
        chunks.append(render_attack_techniques(body.att_ck, formatter))
    return "".join(chunks)


def _render_reference_value(value: str, formatter: MarkdownFormatter) -> str:
    if value.startswith(("http://", "https://")):
        return formatter.link(value, value)
    return value


def _render_vocab_label(field: str, key: str) -> str:
    entry = enrich(field, key)
    if entry.label != key:
        return f"{entry.label} (`{key}`)"
    return key


def _platform_alert_title(config: object) -> str | None:
    alert = getattr(config, "alert", None)
    title = getattr(alert, "title", None) if alert is not None else None
    if title:
        return str(title)
    details = getattr(config, "details", None)
    details_name = getattr(details, "name", None) if details is not None else None
    if details_name:
        return str(details_name)
    return None


def _platform_entity_mappings(config: object) -> list[str]:
    entities = getattr(config, "entities", None)
    if not entities:
        return []

    rendered: list[str] = []
    for entity in entities:
        mappings = getattr(entity, "mappings", None) or []
        pairs = ", ".join(
            f"{mapping.identifier} -> {mapping.column}" for mapping in mappings
        )
        rendered.append(f"{entity.entity}: {pairs}" if pairs else str(entity.entity))
    return rendered


def _platform_query(config: object) -> str | None:
    query = getattr(config, "query", None)
    if isinstance(query, str) and query.strip():
        return query

    search = getattr(config, "search", None)
    if isinstance(search, str) and search.strip():
        return search

    condition = getattr(config, "condition", None)
    if condition is None:
        return None

    single_event = getattr(condition, "single_event", None)
    single_query = getattr(single_event, "query", None) if single_event is not None else None
    if isinstance(single_query, str) and single_query.strip():
        return single_query

    correlation = getattr(condition, "correlation", None)
    sub_queries = getattr(correlation, "sub_queries", None) if correlation is not None else None
    if not sub_queries:
        return None

    fragments = [
        sub_query.query
        for sub_query in sub_queries
        if isinstance(getattr(sub_query, "query", None), str) and sub_query.query.strip()
    ]
    if fragments:
        return "\n\n".join(fragments)
    return None


def render_criticality(threat: ThreatVector, formatter: MarkdownFormatter) -> str:
    criticality = enrich("criticality", threat.criticality)
    content = f"**{criticality.label}**"
    if criticality.description:
        content = f"{content} - {criticality.description}"
    return formatter.heading(2, "Criticality") + formatter.paragraph(content)


def render_terrain(threat: ThreatBody, formatter: MarkdownFormatter) -> str:
    """Render explanatory terrain prose."""
    return formatter.heading(2, "Terrain") + formatter.paragraph(threat.terrain)


def render_surface(threat: ThreatBody, formatter: MarkdownFormatter) -> str:
    """Render surface vocabulary values with enrichment."""
    if not threat.surface:
        return ""
    chunks = [formatter.heading(2, "Surface")]
    for value in threat.surface:
        stage_details = fw.get_vocab_stage_details("surface", value)
        if stage_details:
            label, description = stage_details
        else:
            entry = enrich("surface", value)
            label = entry.label
            description = entry.description
        quote = f"> **{label}**\n"
        if description:
            quote += f"> {description}\n"
        chunks.append(quote + "\n")
    return "".join(chunks)


def render_threat_assessment(threat: ThreatBody, formatter: MarkdownFormatter) -> str:
    rows = [
        _assessment_row("Severity", "severity", threat.severity, formatter),
        _assessment_row("Impact", "impact", threat.impact, formatter),
        _assessment_row("Leverage", "leverage", threat.leverage, formatter),
        _assessment_row("Viability", "viability", threat.viability, formatter),
    ]
    killchain = _as_list(threat.killchain)
    if killchain:
        rows.append(_assessment_row("Kill Chain", "killchain", killchain, formatter))
    return (
        formatter.heading(2, "Threat Assessment")
        + formatter.table(["Dimension", "Assessment", "Description"], rows)
        + "\n"
    )


def render_actors(threat: ThreatBody, formatter: MarkdownFormatter) -> str:
    if not threat.actors:
        return ""
    rows: list[list[str]] = []
    for actor in threat.actors:
        actor_meta = enrich("actors", actor)
        source = fw.get_vocab_entry("actors", actor, field="tide.vocab.stages")
        rows.append(
            [
                _entry_link(actor_meta, actor_meta.label, formatter),
                f"`{actor}`",
                _table_cell(_stringify(source)),
                _table_cell(actor_meta.description),
            ]
        )
    return (
        formatter.heading(2, "Actors")
        + formatter.table(["Actor", "ID", "Source", "Description"], rows)
        + "\n"
    )


def render_attack_techniques(techniques: list[str], formatter: MarkdownFormatter) -> str:
    rows = []
    for technique in techniques:
        entry = enrich_technique(technique)
        rows.append(
            [
                f"`{technique}`",
                _entry_link(entry, technique, formatter),
                _table_cell(entry.description),
            ]
        )
    return (
        formatter.heading(2, "ATT&CK Techniques")
        + formatter.table(["Technique", "Name", "Description"], rows)
        + "\n"
    )


def _assessment_row(
    title: str,
    vocab: str,
    value: str | Iterable[str],
    formatter: MarkdownFormatter,
) -> list[str]:
    values = [value] if isinstance(value, str) else list(value)
    entries = [enrich(vocab, item) for item in values]
    assessment = "<br>".join(_entry_link(entry, entry.key, formatter) for entry in entries)
    description = "<br>".join(_table_cell(entry.description or "-") for entry in entries)
    return [title, assessment, description]


def _entry_link(entry, fallback: str, formatter: MarkdownFormatter) -> str:
    link = entry.raw.get("link") if isinstance(entry.raw, dict) else None
    label = _table_cell(entry.label or fallback)
    if isinstance(link, str) and link.startswith(("http://", "https://")):
        return formatter.link(label, link)
    return label


def _as_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return value


def _stringify(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _table_cell(value: str) -> str:
    return value.replace("\n", " ").replace("|", "\\|").strip() or "-"


def _render_signal_meta(signal: DetectionSignal) -> list[str]:
    severity = enrich("severity", signal.severity).label
    methodology = enrich("detection.methodology", signal.methodology).label
    meta_lines = [
        f"- **Severity**: {severity}",
        f"- **Methodology**: {methodology}",
    ]
    if signal.effort is not None:
        meta_lines.append(f"- **Effort**: {signal.effort}")
    return [line + "\n" for line in meta_lines]


def _render_signal_data(signal: DetectionSignal, formatter: MarkdownFormatter) -> str:
    lines = [formatter.heading(4, "Data")]
    lines.append(f"- **Availability**: {signal.data.availability}")
    lines.append(f"- **Requirements**: {signal.data.requirements}")
    if signal.data.logsources:
        lines.append("- **Log sources**: " + ", ".join(signal.data.logsources))
    return "\n".join(lines) + "\n"


def _render_signal_entities(signal: DetectionSignal) -> str:
    entities = [enrich("signal.entities", entity).label for entity in signal.entities]
    return "- **Entities**: " + ", ".join(entities) + "\n"


def _render_signal_detectors(
    detectors: list[ExternalDetector], formatter: MarkdownFormatter
) -> str:
    lines = [formatter.heading(4, "Detectors")]
    for detector in detectors:
        detector_info = (
            f"- **{detector.name}** ({detector.technology}): {detector.description}"
        )
        if detector.link:
            detector_info += f" ({formatter.link('Reference', detector.link)})"
        lines.append(detector_info)
    return "\n".join(lines) + "\n"


def _render_signal_examples(examples: list[DetectionExample], formatter: MarkdownFormatter) -> str:
    lines = [formatter.heading(4, "Examples")]
    for index, example in enumerate(examples, start=1):
        lines.append(f"{index}. {example.description}")
        lines.append(f"   - **Link**: {formatter.link(example.link, example.link)}")
        if example.query:
            language = example.language or "text"
            lines.append(formatter.code_block(language, example.query))
    return "\n".join(lines) + "\n"


def _rule_coverage_label(
    rule_uuid: str,
    formatter: MarkdownFormatter,
    catalog: DocumentationCatalog,
    *,
    from_folder: str,
    uuid_permalinks: bool,
    wiki_links: bool,
    resolve_name: Callable[[str], str] | None,
) -> str:
    if catalog.resolve_record(rule_uuid) is not None:
        return object_link(
            formatter,
            catalog,
            rule_uuid,
            from_folder=from_folder,
            uuid_permalinks=uuid_permalinks,
            wiki=wiki_links,
        )
    if resolve_name is not None:
        return f"{resolve_name(rule_uuid)} (`{rule_uuid}`)"
    return f"`{rule_uuid}`"
