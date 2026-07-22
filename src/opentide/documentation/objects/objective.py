"""Objective object renderer."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import render_relations_diagram
from opentide.documentation.objects.base import ObjectRenderer
from opentide.documentation.parts import sections
from opentide.models.objective import DetectionObjective


class ObjectiveRenderer(ObjectRenderer):
    """Render detection objectives to markdown."""

    def render(self, obj: DetectionObjective) -> str:
        objective = obj
        blocks = [
            self.title_block(objective.name),
            sections.render_metadata(objective.metadata, self.formatter),
            sections.render_references(objective.references, self.formatter),
            sections.render_description(objective.objective.description, self.formatter),
            sections.render_objective_meta(objective, self.formatter),
            sections.render_signals(objective, self.formatter),
            sections.render_signal_mdr_coverage(
                objective,
                self.formatter,
                resolve_name=self.catalog.resolve_name,
            ),
            self._relations(objective),
        ]
        return self.assemble(blocks)

    def _relations(self, objective: DetectionObjective) -> str:
        diagram = render_relations_diagram(
            self.formatter,
            self.catalog,
            uuid=objective.metadata.uuid,
            name=objective.name,
            direction=self.ctx.relations_direction,
        )
        if not diagram:
            return ""
        return self.formatter.heading(2, "Relations") + diagram


def render_objective_page(
    objective: DetectionObjective,
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
) -> str:
    """Render markdown for an objective object."""
    return ObjectiveRenderer(ctx, catalog).render(objective)
