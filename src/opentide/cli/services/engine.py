"""Shared pieces of the commands that run the analysis engine.

``validate`` (its queries check), ``validate query``, ``lint`` (its queries
check), ``doctor`` and MCP ``validate_query`` call :mod:`opentide.analysis`;
this module turns what it returns, and its one failure, into results the CLI
renders.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from opentide.cli.ui.contract import NextAction
from opentide.cli.ui.glyphs import glyph

if TYPE_CHECKING:
    from opentide.analysis import EngineUnavailableError
    from opentide.cli.ui.diagnostics import Diagnostic


def engine_unavailable_result(exc: EngineUnavailableError, **fields: object) -> dict[str, object]:
    """The failed result of a command whose engine does not load: exit 1, never a skip."""
    return {
        **fields,
        "status": "failed",
        "message": str(exc),
        "advice": exc.advice,
        "_exit_code": 1,
        "_failure_code": exc.code,
        "_next_actions": [NextAction("opentide doctor", "check the installation")],
    }


def findings_summary(diagnostics: Sequence[Diagnostic]) -> dict[str, int]:
    """Counts by severity, and how many files hold an error or a warning."""

    def files_with(severity: str) -> int:
        return len({item.path for item in diagnostics if item.severity == severity and item.path})

    return {
        "errors": sum(1 for item in diagnostics if item.severity == "error"),
        "warnings": sum(1 for item in diagnostics if item.severity == "warning"),
        "notes": sum(1 for item in diagnostics if item.severity == "note"),
        "error_files": files_with("error"),
        "warning_files": files_with("warning"),
    }


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def findings_outcome(
    summary: Mapping[str, int], *, checked: str, failed: bool, clean: str
) -> tuple[str, str | None]:
    """The outcome line of a run that counts findings, and its kind when the status does not say.

    ``12 queries valid`` (*clean*) when nothing was found, ``12 queries valid ·
    2 notes`` with notes alone; ``! 2 warnings in 1 file · 12 queries checked``
    (kind ``warning``) when it passes with warnings; ``3 errors in 2 files ·
    12 queries checked`` when it fails (*checked* is ``12 queries``). Under
    ``--strict`` a run fails on warnings alone, and the line counts those.
    """
    sep = f" {glyph('separator')} "
    errors, warnings, notes = (summary.get(key, 0) for key in ("errors", "warnings", "notes"))
    if errors or warnings:
        if errors:
            counted, files = plural(errors, "error"), summary.get("error_files", 0)
        else:
            counted, files = plural(warnings, "warning"), summary.get("warning_files", 0)
        where = f" in {plural(files, 'file')}" if files else ""
        line = f"{counted}{where}{sep}{checked} checked"
        return line, None if failed else "warning"
    return (f"{clean}{sep}{plural(notes, 'note')}" if notes else clean), None
