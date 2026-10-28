"""Results of ``opentide lsp check`` (``lsp start`` prints no document: stdout is the protocol)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from opentide.cli.ui.results.base import (
    CommandDocument,
    EngineDiagnosticModel,
    EngineVersions,
    ResultModel,
)


class CatalogModel(ResultModel):
    """The Tide catalog the engine used."""

    source: Literal["workspace", "bundled"] = Field(
        description="workspace: .opentide/lsp/catalogs/ from opentide generate schemas"
    )
    opentide: str = Field(description="The opentide version the catalog was generated from")
    path: str | None = Field(description="The workspace catalog folder")
    problem: str | None = Field(description="Why the workspace catalog was not used")


class LspCheckResult(CommandDocument):
    """``opentide lsp check``: the diagnostics an editor shows, for each file."""

    files_checked: int | None = None
    diagnostics: list[EngineDiagnosticModel] = Field(default_factory=list)
    catalog: CatalogModel | None = None
    engine: EngineVersions | None = None
    unmatched: list[str] = Field(
        default_factory=list, description="Paths that name no file or folder"
    )
    advice: str | None = None
