"""Object renderer base class: the parts every page shares."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.diagram.builders import (
    coverage_diagram,
    relations_diagram,
    render_diagram,
)
from opentide.documentation.diagram.model import NodeKind
from opentide.documentation.markdown.links import render_link
from opentide.documentation.markdown.page import Page, Section, section
from opentide.documentation.markdown.text import first_sentence, inline_code
from opentide.documentation.parts import common
from opentide.documentation.vocabulary import enrich
from opentide.models.metadata import ObjectMetadata, ObjectReferences


class ObjectRenderer(ABC):
    """Base renderer: builds a :class:`Page` from ordered sections."""

    folder: str = ""
    kind: NodeKind = NodeKind.rule
    #: What the object is, in the subtitle and the breadcrumb.
    noun: str = "Object"
    #: The folder index's title, as the breadcrumb names it.
    index_title: str = ""

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

    def page(self, title: str, metadata: ObjectMetadata, description: str | None) -> Page:
        """A page with its header: breadcrumb, title, subtitle, TLP banner and description.

        The title is front matter for GitLab UUID permalinks.
        """
        frontmatter = self.ctx.uuid_permalinks and self.wiki_links
        page = Page(self.formatter, title, frontmatter=frontmatter, breadcrumb=self._breadcrumb())
        page.add_lead(
            self._subtitle(metadata),
            self._tlp_banner(metadata.tlp),
            common.prose(self.formatter, description),
        )
        return page

    def _breadcrumb(self) -> str:
        """``Catalogue / Detection rules``: the way back to the indexes.

        Azure DevOps addresses wiki pages by name alone, and every index page is
        named ``README``, so its pages go without one.
        """
        if self.ctx.flavor.value == "azure_devops" or not self.index_title:
            return ""
        root = render_link(self.formatter, "Catalogue", "../README.md", wiki=self.wiki_links)
        index = render_link(self.formatter, self.index_title, "README.md", wiki=self.wiki_links)
        return self.formatter.paragraph(f"{root} / {index}")

    def _subtitle(self, metadata: ObjectMetadata) -> str:
        """``*Detection rule · rule::1.0 · version 3 · modified 2026-01-02 · TLP:CLEAR*``."""
        parts = [
            self.noun,
            inline_code(metadata.schema_id),
            f"version {metadata.version}",
            f"modified {metadata.modified}",
            common.tlp_marking(metadata.tlp),
        ]
        return self.formatter.paragraph("*" + " · ".join(part for part in parts if part) + "*")

    def _tlp_banner(self, tlp: str) -> str:
        """A warning for any marking that limits who may read the page."""
        if common.tlp_marking(tlp) in {"", "TLP:CLEAR", "TLP:WHITE"}:
            return ""
        entry = enrich("tlp", tlp)
        text = f"**{common.tlp_marking(tlp)}**"
        if entry.description:
            text += f": {first_sentence(entry.description)}"
        return self.formatter.callout("warning", text)

    def coverage_section(self, uuid: str, name: str) -> Section:
        """The coverage diagram (or a relations diagram) and the related-objects table."""
        title = "Detection coverage"
        diagram = coverage_diagram(self.catalog, uuid, name=name)
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
