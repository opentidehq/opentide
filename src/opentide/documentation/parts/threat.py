"""Threat sections: overview, assessment, surface, actors, CVE and chaining."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from opentide.documentation.catalog import CoverageGraph
from opentide.documentation.diagram.builders import render_diagram, threat_killchain_diagram
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.page import join, key_value_table
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
from opentide.documentation.vocabulary import (
    actor_aliases,
    chaining_relation,
    enrich,
    killchain_stage,
    vocabulary_order,
)
from opentide.generation import framework as fw
from opentide.models.threat import ThreatBody, ThreatVector
from opentide.vulnerability_lookup import (
    CveSettings,
    EpssScore,
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


def overview(
    threat: ThreatVector,
    links: Links,
    *,
    coverage: tuple[int, int],
    cves: CveFindings | None = None,
) -> str:
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
        ("CVE", cve_overview(cves)),
        ("Detection coverage", detection),
    ]
    return key_value_table(links.formatter, rows, headers=("Property", "Value"))


#: Affected products listed under a CVE; the rest are counted.
AFFECTED_SHOWN = 4

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
    stages = ", ".join(
        dict.fromkeys(killchain_stage(phase) for phase in phases if killchain_stage(phase))
    )
    context = f"{noun} {where} of {len(order)}" + (f", stage {stages}" if stages else "")
    return formatter.paragraph(f"**Kill chain** ({context}): {window}")


def killchain_map(threat: ThreatVector, links: Links) -> str:
    """The kill-chain map: this threat's phase, and those of the threats chained to it."""
    network = links.catalog.chaining_network(threat.metadata.uuid)
    related: dict[str, list[str]] = {}
    if isinstance(network, CoverageGraph):
        for node in network.nodes:
            if node.uuid != threat.metadata.uuid and node.killchain:
                related.setdefault(node.killchain, []).append(node.name)
    diagram = threat_killchain_diagram(killchain_phases(threat.threat), related=related)
    return render_diagram(links.formatter, diagram)


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


#: Aliases of an ATT&CK group shown under its name; the rest are counted.
ALIASES_SHOWN = 4


def actors_table(body: ThreatBody, formatter: MarkdownFormatter) -> str:
    if not body.actors:
        return ""
    rows: list[list[str]] = []
    for actor in body.actors:
        meta = enrich("actors", actor.name)
        source = fw.get_vocab_entry("actors", actor.name, field="tide.vocab.stages")
        sighting = actor.sighting or ""
        name = entry_link(meta, meta.label, formatter)
        aliases = actor_aliases(actor.name)
        if aliases:
            shown = ", ".join(table_cell(alias) for alias in aliases[:ALIASES_SHOWN])
            more = len(aliases) - ALIASES_SHOWN
            name += f"<br>*also {shown}{f' and {more} more' if more > 0 else ''}*"
        rows.append(
            [
                name,
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


@dataclass(frozen=True)
class CveFindings:
    """What Vulnerability-Lookup said about a threat's CVEs, looked up once per page."""

    identifiers: tuple[str, ...]
    settings: CveSettings
    #: Whether details were fetched (``[cve] retrieve_details``).
    enriched: bool = False
    records: Mapping[str, VulnerabilityRecord] = field(default_factory=dict)
    epss: Mapping[str, EpssScore] = field(default_factory=dict)
    missing: tuple[str, ...] = ()
    #: Whether any lookup failed: the page still links every identifier.
    unreachable: bool = False

    def exploited(self) -> list[tuple[str, VulnerabilityRecord]]:
        """The CVEs known to be exploited: in CISA's KEV catalog, or SSVC ``active``."""
        return [
            (cve, record)
            for cve, record in self.records.items()
            if record.kev_added or (record.exploitation or "").lower() == "active"
        ]


def lookup_cves(
    cve_list: list[str] | None,
    *,
    client: VulnerabilityLookupClient | None = None,
    retrieve_details: bool | None = None,
) -> CveFindings | None:
    """Resolve *cve_list* against Vulnerability-Lookup, with EPSS scores; ``None`` when empty."""
    identifiers: list[str] = []
    seen: set[str] = set()
    for cve in normalize_identifiers(cve_list):
        key = lookup_identifier(cve)
        if key not in seen:
            seen.add(key)
            identifiers.append(cve)
    if not identifiers:
        return None
    settings = load_cve_settings()
    enrich_details = settings.retrieve_details if retrieve_details is None else retrieve_details
    if not enrich_details:
        return CveFindings(tuple(identifiers), settings)
    apply_cve_proxy_settings(settings)
    lookup = client or VulnerabilityLookupClient(settings)
    records: dict[str, VulnerabilityRecord] = {}
    scores: dict[str, EpssScore] = {}
    missing: list[str] = []
    unreachable = False
    for cve in identifiers:
        try:
            record = lookup.get(cve, with_linked=True)
        except VulnerabilityLookupError:
            unreachable = True
            continue
        if record is None:
            missing.append(cve)
            continue
        records[cve] = record
        if record.cve_id:
            try:
                score = lookup.epss(record.cve_id)
            except VulnerabilityLookupError:
                unreachable = True
                continue
            if isinstance(score, EpssScore):
                scores[cve] = score
    return CveFindings(
        tuple(identifiers),
        settings,
        enriched=True,
        records=records,
        epss=scores,
        missing=tuple(missing),
        unreachable=unreachable,
    )


def cve_body(
    cve_list: list[str] | None,
    formatter: MarkdownFormatter,
    *,
    client: VulnerabilityLookupClient | None = None,
    retrieve_details: bool | None = None,
) -> str:
    """CVE identifiers as Vulnerability-Lookup links, with optional API enrichment."""
    findings = lookup_cves(cve_list, client=client, retrieve_details=retrieve_details)
    return render_cves(findings, formatter)


def render_cves(findings: CveFindings | None, formatter: MarkdownFormatter) -> str:
    """The CVE section: severity, exploit likelihood, exploitation and weakness per CVE."""
    if findings is None:
        return ""
    settings = findings.settings
    source_note = formatter.paragraph(
        "Identifiers link to [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu), "
        "which aggregates CVE, GHSA, CSAF, NVD, and related feeds."
    )
    if not findings.enriched:
        bullets = "".join(
            f"- {formatter.link(cve, page_url_for(cve, settings))}\n"
            for cve in findings.identifiers
        )
        return source_note + bullets

    rows: list[list[str]] = []
    details: list[str] = []
    for cve in findings.identifiers:
        record = findings.records.get(cve)
        if record is None:
            note = (
                "Not found in Vulnerability-Lookup."
                if cve in findings.missing
                else "Details unavailable from Vulnerability-Lookup."
            )
            link = formatter.link(cve, page_url_for(cve, settings))
            rows.append([link, "-", "-", "-", "-", note])
            continue
        epss = findings.epss.get(cve)
        rows.append(_cve_row(record, formatter, fallback_id=cve, settings=settings, epss=epss))
        details.append(_cve_detail(record))
    table = formatter.table(
        ["Identifier", "Severity", "EPSS", "Exploitation", "Weakness", "Published"], rows
    )
    parts = [source_note, table]
    if details:
        parts.append("\n".join(details) + "\n")
    if findings.missing:
        parts.append(
            formatter.paragraph(
                "Could not resolve: " + ", ".join(f"`{cve}`" for cve in findings.missing) + "."
            )
        )
    if findings.unreachable:
        parts.append(
            formatter.paragraph(
                "Vulnerability-Lookup was unreachable for at least one identifier; "
                "links still point at the CIRCL record page."
            )
        )
    parts.append(
        formatter.paragraph(
            "*EPSS: FIRST's probability of exploitation in the next 30 days. Exploitation: "
            "CISA's Known Exploited Vulnerabilities catalog, else its SSVC assessment.*"
        )
    )
    return join(parts)


def cve_overview(findings: CveFindings | None) -> str:
    """``2 CVEs (highest CVSS 10.0, 1 known exploited)`` for the overview table."""
    if findings is None:
        return ""
    text = plural(len(findings.identifiers), "CVE")
    facts: list[str] = []
    scores = [record.cvss.score for record in findings.records.values() if record.cvss]
    if scores:
        facts.append(f"highest CVSS {max(scores):.1f}")
    exploited = findings.exploited()
    if exploited:
        facts.append(f"{len(exploited)} known exploited")
    return f"{text} ({', '.join(facts)})" if facts else text


def exploited_banner(findings: CveFindings | None, formatter: MarkdownFormatter) -> str:
    """A warning naming the CVEs exploited in the wild."""
    exploited = findings.exploited() if findings is not None else []
    if not exploited:
        return ""
    named = []
    for cve, record in exploited:
        source = f"CISA KEV since {record.kev_added}" if record.kev_added else "CISA SSVC: active"
        named.append(f"{inline_code(record.identifier or cve)} ({source})")
    verb = "is" if len(named) == 1 else "are"
    return formatter.callout(
        "warning", f"{', '.join(named)} {verb} known to be exploited in the wild."
    )


def _cve_row(
    record: VulnerabilityRecord,
    formatter: MarkdownFormatter,
    *,
    fallback_id: str,
    settings: CveSettings,
    epss: EpssScore | None,
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
    if record.cvss is not None:
        cvss = record.cvss
        severity = f"**{cvss.score:.1f}** {cvss.severity}".strip() + f"<br>CVSS {cvss.version}"
    else:
        severity = table_cell(record.severity or record.state or "-")
    likelihood = f"{_share(epss.probability)}<br>top {_share(1 - epss.percentile)}" if epss else "-"
    weakness = join_lines(
        (formatter.link(w.identifier, w.url) if w.url else w.identifier)
        + (f" {table_cell(w.name)}" if w.name else "")
        for w in record.weaknesses
    )
    return [
        label,
        severity,
        likelihood,
        _exploitation(record),
        weakness or "-",
        record.published or "-",
    ]


def _share(value: float) -> str:
    """A probability as a percentage that never rounds to a certainty: ``>99.9%``, ``<0.1%``."""
    percent = value * 100
    if percent >= 99.95:
        return ">99.9%"
    if percent < 0.05:
        return "<0.1%"
    return f"{percent:.1f}%"


def _exploitation(record: VulnerabilityRecord) -> str:
    if record.kev_added:
        return f"**Known exploited**<br>CISA KEV, {record.kev_added}"
    state = (record.exploitation or "").lower()
    return {
        "active": "**Active**<br>CISA SSVC",
        "poc": "Proof of concept<br>CISA SSVC",
        "public poc": "Proof of concept<br>CISA SSVC",
        "none": "None reported<br>CISA SSVC",
    }.get(state, "-")


def _cve_detail(record: VulnerabilityRecord) -> str:
    """One line per CVE: what it is, what it affects, how it scores."""
    summary = truncate(record.title or record.description or "", 280) or "no summary"
    parts = [f"- **{record.identifier}**: {summary.rstrip('.')}."]
    if record.affected:
        shown = ", ".join(record.affected[:AFFECTED_SHOWN])
        more = len(record.affected) - AFFECTED_SHOWN
        parts.append(f"Affects {shown}{f' and {more} more' if more > 0 else ''}.")
    if record.cvss is not None and record.cvss.vector:
        parts.append(f"Vector {inline_code(record.cvss.vector)}.")
    return " ".join(parts)
