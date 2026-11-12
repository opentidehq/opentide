"""Threat object renderer."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import chaining_diagram, render_diagram
from opentide.documentation.diagram.model import NodeKind
from opentide.documentation.markdown.page import Section, section
from opentide.documentation.objects.base import ObjectRenderer
from opentide.documentation.parts import common
from opentide.documentation.parts import threat as parts
from opentide.models.threat import ThreatVector


class ThreatRenderer(ObjectRenderer):
    """Render threat vectors to markdown.

    Reading order: the threat (overview, description, terrain, assessment),
    who and what it involves, how it chains with other threats, and how it is
    detected.
    """

    folder = "threats"
    kind = NodeKind.threat
    noun = "Threat vector"
    index_title = "Threat vectors"

    def render(self, obj: ThreatVector) -> str:
        threat = obj
        body = threat.threat
        uuid = threat.metadata.uuid
        coverage = parts.coverage_counts(self.catalog.coverage_graph(uuid))
        page = self.page(threat.name, threat.metadata, body.description)
        page.add_lead(parts.overview(threat, self.links, coverage=coverage))
        if coverage[0] == 0:
            page.add_lead(
                self.formatter.callout(
                    "warning", "No detection objective addresses this threat vector yet."
                )
            )
        page.add(
            section(
                "Assessment",
                parts.criticality_body(threat, self.formatter),
                parts.terrain_body(body, self.formatter),
                parts.killchain_strip(body, self.formatter),
                parts.assessment_table(body, self.formatter),
            )
        )
        page.add(section("Surface", parts.surface_table(body, self.formatter)))
        page.add(section("Actors", parts.actors_table(body, self.formatter)))
        page.add(
            section("ATT&CK techniques", common.attack_table(body.mitre_attack, self.formatter))
        )
        page.add(section("CVE", parts.cve_body(body.cve, self.formatter)))
        page.add(self._chaining(threat))
        page.add(self.coverage_section(uuid, threat.name))
        page.add(self.references_section(threat.references))
        page.add(self.metadata_section(threat.metadata))
        return page.render()

    def _chaining(self, threat: ThreatVector) -> Section:
        diagram = chaining_diagram(self.catalog, threat.metadata.uuid, name=threat.name)
        return section(
            "Chaining",
            render_diagram(self.formatter, diagram),
            children=[section("Chaining relations", parts.chaining_table(threat, self.links))],
        )


def render_threat_page(
    threat: ThreatVector,
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
) -> str:
    """Render markdown for a threat object."""
    return ThreatRenderer(ctx, catalog).render(threat)
