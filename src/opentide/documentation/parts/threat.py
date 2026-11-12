"""Threat sections: overview, assessment, surface, actors, CVE and chaining."""

from __future__ import annotations

from collections.abc import Iterable

from opentide.documentation.catalog import CoverageGraph
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.page import key_value_table
from opentide.documentation.markdown.text import (
    first_sentence,
    inline_code,
    join_lines,
    plural,
    stringify,
    table_cell,
    truncate,
)
from opentide.documentation.parts.common import Links, entry_link, technique_links
from opentide.documentation.vocabulary import chaining_relation, enrich, vocabulary_order
from opentide.generation import framework as fw
from opentide.models.threat import ThreatBody, ThreatVector
from opentide.vulnerability_lookup import (
    CveSettings,
    VulnerabilityLookupClient,
    VulnerabilityLookupError,
    VulnerabilityRecord,
    apply_cve_proxy_settings,
    load_cve_settings,
    lookup_identifier,
    normalize_identifiers,
    page_url_for,
)


def killchain_phases(body: ThreatBody) -> list[str]:
    value = body.killchain
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def coverage_counts(graph: object) -> tuple[int, int]:
    """``(objectives, rules)`` on the threat's coverage graph."""
    if not isinstance(graph, CoverageGraph):
        return 0, 0
    objectives = sum(1 for node in graph.nodes if node.object_type == "objective")
    rules = sum(1 for node in graph.nodes if node.object_type == "rule")
    return objectives, rules


def overview(threat: ThreatVector, links: Links, *, coverage: tuple[int, int]) -> str:
    body = threat.threat
    objectives, rules = coverage
    detection = (
        f"{plural(objectives, 'objective')}, {plural(rules, 'rule')}" if objectives else "None"
    )
    actors = [enrich("actors", actor.name).label for actor in body.actors or []]
    rows = [
        ("Criticality", enrich("criticality", threat.criticality).label),
        ("Severity", enrich("severity", body.severity).label),
        ("Kill chain", ", ".join(killchain_phases(body))),
        ("Surface", ", ".join(_surface_label(value)[0] for value in body.surface)),
        ("Actors", table_cell(", ".join(actors))),
        ("ATT&CK", technique_links(body.mitre_attack, links.formatter)),
        ("Detection coverage", detection),
    ]
    return key_value_table(links.formatter, rows, headers=("Property", "Value"))


#: Phases shown on each side of the threat's own in the kill-chain window.
KILLCHAIN_CONTEXT = 2


def killchain_strip(body: ThreatBody, formatter: MarkdownFormatter) -> str:
    """Where the threat sits on the kill chain: its phases in bold, with their neighbours.

    ``**Kill chain** (phase 13 of 18): … Privilege Escalation → Execution →
    **Credential Access** → Lateral Movement → Collection …``
    """
    phases = killchain_phases(body)
    order = vocabulary_order("killchain")
    positions = [order.index(phase) for phase in phases if phase in order]
    if not positions:
        return ""
    first = max(min(positions) - KILLCHAIN_CONTEXT, 0)
    last = min(max(positions) + KILLCHAIN_CONTEXT, len(order) - 1)
    steps = [f"**{phase}**" if phase in phases else phase for phase in order[first : last + 1]]
    window = " → ".join(steps)
    if first > 0:
        window = "… " + window
    if last < len(order) - 1:
        window += " …"
    where = ", ".join(str(position + 1) for position in sorted(positions))
    noun = "phase" if len(positions) == 1 else "phases"
    return formatter.paragraph(f"**Kill chain** ({noun} {where} of {len(order)}): {window}")


def criticality_body(threat: ThreatVector, formatter: MarkdownFormatter) -> str:
    entry = enrich("criticality", threat.criticality)
    text = f"**Criticality: {entry.label}**"
    if entry.description:
        text += f". {' '.join(entry.description.split())}"
    return formatter.paragraph(text)


def terrain_body(body: ThreatBody, formatter: MarkdownFormatter) -> str:
    return formatter.paragraph(f"**Terrain:** {body.terrain.strip()}") if body.terrain else ""


def assessment_table(body: ThreatBody, formatter: MarkdownFormatter) -> str:
    rows = [
        _assessment_row("Severity", "severity", body.severity, formatter),
        _assessment_row("Impact", "impact", body.impact, formatter),
        _assessment_row("Leverage", "leverage", body.leverage, formatter),
        _assessment_row("Viability", "viability", body.viability, formatter),
    ]
    phases = killchain_phases(body)
    if phases:
        rows.append(_assessment_row("Kill chain", "killchain", phases, formatter))
    return formatter.table(["Dimension", "Assessment", "Description"], rows)


def _assessment_row(
    title: str, vocab: str, value: str | Iterable[str], formatter: MarkdownFormatter
) -> list[str]:
    values = [value] if isinstance(value, str) else list(value)
    entries = [enrich(vocab, item) for item in values]
    assessment = join_lines(entry_link(entry, entry.key, formatter) for entry in entries)
    description = join_lines(table_cell(entry.description or "-") for entry in entries)
    return [title, assessment, description]


def surface_table(body: ThreatBody, formatter: MarkdownFormatter) -> str:
    if not body.surface:
        return ""
    rows = []
    for value in body.surface:
        label, description = _surface_label(value)
        rows.append([table_cell(label), table_cell(description)])
    return formatter.table(["Surface", "Description"], rows)


def _surface_label(value: str) -> tuple[str, str]:
    details = fw.get_vocab_stage_details("surface", value)
    if details:
        return details
    entry = enrich("surface", value)
    return entry.label, entry.description


def actors_table(body: ThreatBody, formatter: MarkdownFormatter) -> str:
    if not body.actors:
        return ""
    rows: list[list[str]] = []
    for actor in body.actors:
        meta = enrich("actors", actor.name)
        source = fw.get_vocab_entry("actors", actor.name, field="tide.vocab.stages")
        sighting = actor.sighting or ""
        rows.append(
            [
                entry_link(meta, meta.label, formatter),
                inline_code(actor.name),
                table_cell(stringify(source)),
                table_cell(sighting or first_sentence(meta.description)),
            ]
        )
    return formatter.table(["Actor", "ID", "Source", "Description"], rows)


def chaining_table(threat: ThreatVector, links: Links) -> str:
    """Each chaining relation the threat declares, with what the relation means."""
    rows: list[list[str]] = []
    for entry in threat.threat.chaining or []:
        target = entry.get("vector") or entry.get("target") or entry.get("uuid") or entry.get("id")
        if not target:
            continue
        key = str(entry.get("relation") or "").strip()
        relation = chaining_relation(key) if key else None
        description = str(entry.get("description") or "").strip()
        if not description and key:
            description = enrich("chaining_relations", key).description
        rows.append(
            [
                inline_code(relation.label) if relation else "related",
                links.to(str(target), with_uuid=links.catalog.resolve_record(str(target)) is None),
                (relation.family or "-") if relation else "-",
                table_cell(description.replace("**", "")),
            ]
        )
    if not rows:
        return ""
    return links.formatter.table(["Relation", "Threat vector", "Family", "Meaning"], rows)


def cve_body(
    cve_list: list[str] | None,
    formatter: MarkdownFormatter,
    *,
    client: VulnerabilityLookupClient | None = None,
    retrieve_details: bool | None = None,
) -> str:
    """CVE identifiers as Vulnerability-Lookup links, with optional API enrichment."""
    identifiers = normalize_identifiers(cve_list)
    if not identifiers:
        return ""

    unique: list[str] = []
    seen_keys: set[str] = set()
    for cve in identifiers:
        key = lookup_identifier(cve)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append(cve)
    identifiers = unique

    settings = load_cve_settings()
    should_enrich = settings.retrieve_details if retrieve_details is None else retrieve_details
    source_note = formatter.paragraph(
        "Identifiers link to [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu), "
        "which aggregates CVE, GHSA, CSAF, NVD, and related feeds."
    )

    if not should_enrich:
        bullets = "".join(
            f"- {formatter.link(cve, page_url_for(cve, settings))}\n" for cve in identifiers
        )
        return source_note + bullets

    apply_cve_proxy_settings(settings)
    lookup = client or VulnerabilityLookupClient(settings)
    rows: list[list[str]] = []
    missing: list[str] = []
    lookup_failed = False
    for cve in identifiers:
        link = formatter.link(cve, page_url_for(cve, settings))
        try:
            record = lookup.get(cve, with_linked=True)
        except VulnerabilityLookupError:
            lookup_failed = True
            rows.append([link, "-", "-", "Details unavailable from Vulnerability-Lookup."])
            continue
        if record is None:
            missing.append(cve)
            rows.append([link, "-", "-", "Not found in Vulnerability-Lookup."])
            continue
        rows.append(_cve_row(record, formatter, fallback_id=cve, settings=settings))

    table = formatter.table(["Identifier", "Published", "Severity", "Summary"], rows)
    warnings = ""
    if missing:
        warnings += formatter.paragraph(
            "Could not resolve: " + ", ".join(f"`{cve}`" for cve in missing) + "."
        )
    if lookup_failed:
        warnings += formatter.paragraph(
            "Vulnerability-Lookup was unreachable for at least one identifier; "
            "links still point at the CIRCL record page."
        )
    return source_note + table + "\n" + warnings


def _cve_row(
    record: VulnerabilityRecord,
    formatter: MarkdownFormatter,
    *,
    fallback_id: str,
    settings: CveSettings,
) -> list[str]:
    ident = record.identifier or fallback_id
    url = record.page_url or page_url_for(ident, settings)
    label = formatter.link(ident, url)
    if record.aliases:
        alias_links = ", ".join(
            formatter.link(alias, page_url_for(alias, settings))
            for alias in record.aliases
            if alias != ident
        )
        if alias_links:
            label = f"{label}<br>{alias_links}"
    summary = record.title or record.description or "-"
    return [
        label,
        record.published or "-",
        record.severity or (record.state or "-"),
        table_cell(truncate(summary, 280)),
    ]
