"""Threat object renderer."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import render_chaining_diagram
from opentide.documentation.markdown.links import object_link
from opentide.documentation.objects.base import ObjectRenderer
from opentide.documentation.parts import sections
from opentide.documentation.vocabulary import enrich
from opentide.models.threat import ThreatVector


class ThreatRenderer(ObjectRenderer):
    """Render threat vectors to markdown."""

    folder = "Threats"

    def render(self, obj: ThreatVector) -> str:
        threat = obj
        blocks = [
            self.title_block(threat.name),
            sections.render_metadata(threat.metadata, self.formatter),
            sections.render_references(threat.references, self.formatter),
            sections.render_threat_body(threat, self.formatter),
            self._chaining(threat),
            self.coverage_block(threat.metadata.uuid, threat.name),
        ]
        return self.assemble(blocks)

    def _chaining(self, threat: ThreatVector) -> str:
        diagram = render_chaining_diagram(
            self.formatter,
            self.catalog,
            uuid=threat.metadata.uuid,
            name=threat.name,
        )
        details = self._chaining_details(threat)
        if not diagram and not details:
            return ""
        return self.formatter.heading(2, "Chaining") + diagram + details

    def _chaining_details(self, threat: ThreatVector) -> str:
        if not threat.threat.chaining:
            return ""
        chunks: list[str] = [self.formatter.heading(3, "Chaining details")]
        for entry in threat.threat.chaining:
            target = (
                entry.get("vector") or entry.get("target") or entry.get("uuid") or entry.get("id")
            )
            if not target:
                continue
            relation_key = str(entry.get("relation") or "").strip()
            relation = enrich("chaining_relations", relation_key) if relation_key else None
            relation_label = relation.label if relation else "Related"
            target_link = object_link(
                self.formatter,
                self.catalog,
                str(target),
                from_folder=self.folder,
                uuid_permalinks=self.ctx.uuid_permalinks,
                wiki=self.wiki_links,
            )
            heading = f"{relation_label} -> {target_link}"
            if relation_key and relation_key != relation_label:
                heading += f" (`{relation_key}`)"
            chunks.append(self.formatter.heading(4, heading))
            description = str(entry.get("description") or "").strip()
            if not description and relation:
                description = relation.description
            if description:
                chunks.append(self.formatter.paragraph(description))
            chunks.append(f"- **Target UUID**: `{target}`\n")
        return "".join(chunks)


def render_threat_page(
    threat: ThreatVector,
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
) -> str:
    """Render markdown for a threat object."""
    return ThreatRenderer(ctx, catalog).render(threat)
