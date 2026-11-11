"""Object renderer base class: the parts every page shares."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import (
    coverage_diagram,
    relations_diagram,
    render_diagram,
)
from opentide.documentation.diagram.model import NodeKind
from opentide.documentation.facts.deployment import PlatformDeployment
from opentide.documentation.markdown.page import Page, Section, section
from opentide.documentation.parts import common
from opentide.models.metadata import ObjectMetadata, ObjectReferences


class ObjectRenderer(ABC):
    """Base renderer: builds a :class:`Page` from ordered sections."""

    folder: str = ""
    kind: NodeKind = NodeKind.rule

    def __init__(self, ctx: DocumentationContext, catalog: DocumentationCatalog) -> None:
        self.ctx = ctx
        self.catalog = catalog
        self.formatter = ctx.formatter
        self.links = common.Links(
            formatter=ctx.formatter,
            catalog=catalog,
            folder=self.folder,
            uuid_permalinks=ctx.uuid_permalinks,
            wiki=self.wiki_links,
        )

    @property
    def wiki_links(self) -> bool:
        return self.ctx.flavor.value in {"gitlab", "azure_devops"}

    @abstractmethod
    def render(self, obj: Any) -> str:
        """Render a typed object to markdown."""

    def page(self, title: str) -> Page:
        """An empty page titled *title*, as front matter for GitLab UUID permalinks."""
        frontmatter = self.ctx.uuid_permalinks and self.wiki_links
        return Page(self.formatter, title, frontmatter=frontmatter)

    def coverage_section(
        self, uuid: str, name: str, *, platforms: Sequence[PlatformDeployment] = ()
    ) -> Section:
        """The coverage diagram (or a relations diagram) and the related-objects table."""
        title = "Detection coverage"
        diagram = coverage_diagram(self.catalog, uuid, name=name, platforms=platforms)
        if diagram is None or diagram.is_trivial():
            title = "Relations"
            diagram = relations_diagram(
                self.catalog,
                uuid,
                name=name,
                kind=self.kind,
                direction=self.ctx.relations_direction,
            )
        related = common.related_table(self.links, uuid, direction=self.ctx.relations_direction)
        return section(
            title,
            render_diagram(self.formatter, diagram),
            children=[section("Related objects", related)],
        )

    def references_section(self, references: ObjectReferences | None) -> Section:
        return section("References", common.references_body(references, self.formatter))

    def metadata_section(self, metadata: ObjectMetadata) -> Section:
        return section("Metadata", common.metadata_table(metadata, self.formatter))
