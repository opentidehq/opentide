"""Objective object renderer."""

from __future__ import annotations

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.model import NodeKind
from opentide.documentation.markdown.page import section
from opentide.documentation.objects.base import ObjectRenderer
from opentide.documentation.parts import common
from opentide.documentation.parts import objective as parts
from opentide.models.objective import DetectionObjective


class ObjectiveRenderer(ObjectRenderer):
    """Render detection objectives to markdown.

    Reading order: the goal (overview, description, composition), the threats
    it answers, its signals, how far rules implement them, then context.
    """

    folder = "objectives"
    kind = NodeKind.objective
    noun = "Detection objective"
    index_title = "Detection objectives"

    def render(self, obj: DetectionObjective) -> str:
        objective = obj
        body = objective.objective
        page = self.page(objective.name, objective.metadata, body.description)
        page.add_lead(
            parts.overview(objective, self.links),
            parts.unimplemented_signals(objective, self.links),
        )
        page.add(section("Composition", parts.composition_body(objective, self.formatter)))
        page.add(section("Threats addressed", parts.threats_body(objective, self.links)))
        page.add(
            section(
                "Signals",
                parts.signals_summary(objective, self.links),
                children=parts.signal_sections(objective, self.links),
            )
        )
        page.add(
            section(
                "ATT&CK techniques", common.attack_table(body.mitre_attack or [], self.formatter)
            )
        )
        page.add(self.coverage_section(objective.metadata.uuid, objective.name))
        page.add(self.references_section(objective.references))
        page.add(self.metadata_section(objective.metadata))
        return page.render()


def render_objective_page(
    objective: DetectionObjective,
    ctx: DocumentationContext,
    catalog: DocumentationCatalog,
) -> str:
    """Render markdown for an objective object."""
    return ObjectiveRenderer(ctx, catalog).render(objective)
