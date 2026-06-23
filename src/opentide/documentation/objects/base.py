"""Object renderer base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.markdown.builder import join_blocks


class ObjectRenderer(ABC):
    """Base renderer composing ordered markdown sections."""

    def __init__(self, ctx: DocumentationContext, catalog: DocumentationCatalog) -> None:
        self.ctx = ctx
        self.catalog = catalog
        self.formatter = ctx.formatter

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
