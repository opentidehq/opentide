"""Results of ``opentide generate`` and its subcommands, and of their deprecated spellings."""

from __future__ import annotations

from pydantic import Field

from opentide.cli.ui.results.base import CommandDocument, Counts, ResultModel


class GenerationStep(ResultModel):
    """One phase of a generation run, as its progress line printed it (#643)."""

    name: str
    status: str
    count: int | None = None
    unit: str | None = None
    seconds: float
    where: str | None = None


class Steps(ResultModel):
    # Added by #643 (flow), declared ahead so either merge order stays green.
    steps: list[GenerationStep] | None = Field(None, description="Each phase that ran")


class GenerateResult(CommandDocument, Steps):
    """A generation phase, several phases or the full pipeline."""

    phases: list[str] | None = Field(None, description="The phases that ran, in order")
    phase: str | None = Field(None, description="The phase that ran, or the one that failed")


class DocsResult(CommandDocument, Steps):
    """``generate docs``: Markdown pages for detection objects."""

    counts: Counts | None = Field(None, description="Pages written, by object family")
    output: str | None = Field(None, description="The documentation directory")
    phase: str | None = Field(None, description="docs, when the phase failed")
    changed_paths: list[str] | None = Field(None, description="With --changed: files changed")
    changed_uuids: list[str] | None = Field(None, description="With --changed: objects changed")
    targets: list[str] | None = Field(None, description="With --changed: objects rewritten")
    scopes: list[str] | None = Field(None, description="With --changed: families rewritten")
    removed: int | None = Field(None, description="With --changed: pages of deleted objects")


class ExportResult(CommandDocument, Steps):
    """``generate exports <target>``: one catalogue export."""

    target: str | None = Field(None, description="navigator, objects or revisions")
    phase: str | None = Field(None, description="exports, when the export failed")


class SkippedImport(ResultModel):
    name: str
    reason: str


class ExtractResult(CommandDocument):
    """``generate extract <platform>``: rules imported from a vendor tenant."""

    import_: str | None = Field(None, alias="import", description="The platform imported from")
    output: str | None = Field(None, description="What the importer printed, under --json")
    tenant: str | None = None
    space: str | None = Field(None, description="Elastic: the Kibana space")
    extracted_count: int | None = None
    skipped: list[SkippedImport] | None = None
    destination: str | None = Field(None, description="The directory the rules were written to")
