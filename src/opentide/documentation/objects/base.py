"""Object renderer base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import (
    render_coverage_diagram,
    render_relations_diagram,
)
from opentide.documentation.markdown.builder import join_blocks
from opentide.documentation.parts import sections


class ObjectRenderer(ABC):
    """Base renderer composing ordered markdown sections."""

    folder: str = ""

    def __init__(self, ctx: DocumentationContext, catalog: DocumentationCatalog) -> None:
        self.ctx = ctx
        self.catalog = catalog
        self.formatter = ctx.formatter

    @property
    def wiki_links(self) -> bool:
        return self.ctx.flavor.value in {"gitlab", "azure_devops"}

    @abstractmethod
    def render(self, obj: Any) -> str:
        """Render a typed object to markdown."""

    def assemble(self, blocks: list[str]) -> str:
        """Join section blocks into a single document."""
        return join_blocks(blocks)

    def title_block(self, title: str) -> str:
        """Render title or frontmatter depending on flavor settings."""
        if self.ctx.uuid_permalinks and self.ctx.flavor.value in {"gitlab", "azure_devops"}:
            return self.formatter.frontmatter(title)
        return self.formatter.heading(1, title)

    def coverage_block(self, uuid: str, name: str) -> str:
        """Coverage Mermaid, or a Relations fallback, plus the related-objects table."""
        coverage = render_coverage_diagram(
            self.formatter,
            self.catalog.coverage_graph(uuid),
            current_uuid=uuid,
        )
        relations = ""
        if not coverage:
            relations = render_relations_diagram(
                self.formatter,
                self.catalog,
                uuid=uuid,
                name=name,
                direction=self.ctx.relations_direction,
            )
        table = sections.render_related_objects(
            self.catalog,
            uuid,
            self.formatter,
            from_folder=self.folder,
            direction=self.ctx.relations_direction,
            uuid_permalinks=self.ctx.uuid_permalinks,
            wiki_links=self.wiki_links,
        )
        if not coverage and not relations and not table:
            return ""
        if coverage:
            heading = self.formatter.heading(2, "Coverage")
        elif relations:
            heading = self.formatter.heading(2, "Relations")
        else:
            heading = ""
        return heading + (coverage or relations) + table
