"""Results of ``opentide migrate vocab-scope``."""

from __future__ import annotations

from pydantic import Field

from opentide.cli.ui.results.base import CommandDocument, ResultModel


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
