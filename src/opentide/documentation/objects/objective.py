"""Objective object renderer."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.objects.base import ObjectRenderer
from opentide.documentation.parts import sections
from opentide.models.objective import DetectionObjective


class ObjectiveRenderer(ObjectRenderer):
    """Render detection objectives to markdown."""

    folder = "Objectives"

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
                self.catalog,
                from_folder=self.folder,
                uuid_permalinks=self.ctx.uuid_permalinks,
                wiki_links=self.wiki_links,
            ),
            self.coverage_block(objective.metadata.uuid, objective.name),
        ]
        return self.assemble(blocks)


def render_objective_page(
    objective: DetectionObjective,
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
) -> str:
    """Render markdown for an objective object."""
    return ObjectiveRenderer(ctx, catalog).render(objective)
