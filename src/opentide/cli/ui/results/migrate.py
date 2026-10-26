"""Results of ``opentide migrate objects`` and ``migrate vocab-scope``."""

from __future__ import annotations

from pydantic import Field

from opentide.cli.ui.results.base import CommandDocument, ResultModel


class LayoutOperation(ResultModel):
    from_: str = Field(alias="from")
    to: str
    action: str = Field(description="move, copy or skip")
    reason: str | None = Field(None, description="Why the path is skipped")


class FolderRename(ResultModel):
    from_: str = Field(alias="from")
    to: str


class MigrateObjectsResult(CommandDocument):
    """``opentide migrate objects``: legacy layout paths moved into the current layout."""

    path: str | None = None
    dry_run: bool | None = None
    copy_: bool | None = Field(None, alias="copy", description="Whether files are copied")
    operations: list[LayoutOperation] = Field(default_factory=list)
    planned: int | None = None
    skipped: int | None = None
    applied: bool | None = None
    case_renamed: list[FolderRename] | None = None
    removed_empty: list[str] | None = None
    advice: str | None = None


class ScopedFieldReport(ResultModel):
    vocab: str
    values: int
    by_status: dict[str, int]
    rewrites: dict[str, str]
    blocked: dict[str, str] = Field(description="Values defined under several stages")


class MigrateVocabScopeResult(CommandDocument):
    """``opentide migrate vocab-scope``: stage-scoped vocabulary values re-prefixed."""

    applied: bool | None = None
    scanned: int | None = None
    changed_files: list[str] = Field(default_factory=list)
    failed_files: dict[str, str] = Field(default_factory=dict)
    fields: dict[str, ScopedFieldReport] = Field(default_factory=dict)
