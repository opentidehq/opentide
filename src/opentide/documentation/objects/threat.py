"""Threat object renderer."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import (
    render_chaining_diagram,
    render_relations_diagram,
)
from opentide.documentation.objects.base import ObjectRenderer
from opentide.documentation.parts import sections
from opentide.models.threat import ThreatVector


class ThreatRenderer(ObjectRenderer):
    """Render threat vectors to markdown."""

    def render(self, obj: ThreatVector) -> str:
        threat = obj
        blocks = [
            self.title_block(threat.name),
            sections.render_metadata(threat.metadata, self.formatter),
            sections.render_threat_body(threat, self.formatter),
            self._chaining(threat),
            self._relations(threat),
        ]
        return self.assemble(blocks)

    def _chaining(self, threat: ThreatVector) -> str:
        diagram = render_chaining_diagram(
            self.formatter,
            self.catalog,
            uuid=threat.metadata.uuid,
            name=threat.name,
        )
        if not diagram:
            return ""
        return self.formatter.heading(2, "Chaining") + diagram

    def _relations(self, threat: ThreatVector) -> str:
        diagram = render_relations_diagram(
            self.formatter,
            self.catalog,
            uuid=threat.metadata.uuid,
            name=threat.name,
        )
        if not diagram:
            return ""
        return self.formatter.heading(2, "Relations") + diagram


def render_threat_page(
    threat: ThreatVector,
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
) -> str:
    """Render markdown for a threat object."""
    return ThreatRenderer(ctx, catalog).render(threat)
