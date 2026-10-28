"""The ``queries`` check: every query an object carries, through the analysis engine.

Off by default; ``opentide validate --deep`` runs it after the default checks,
and ``--check queries`` alone. Each query is checked in its own language with
its platform's profile (Sentinel or Defender KQL, SPL, the Elastic languages,
Carbon Black Lucene), offline. Errors and warnings become validation issues
at the place in the file the engine names; the engine's notes (hints) are left
to ``opentide validate query`` and ``opentide lsp check``.

A missing engine is an ``engine_unavailable`` error: the check never skips.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from opentide.validation.issues import ValidationIssue

#: ``ValidationIssue.context["source"]`` of the issues this check reports.
ENGINE_SOURCE = "engine"


@dataclass(frozen=True)
class QueryObject:
    """An object file whose queries the check reads."""

    file_path: Path
    uuid: str
    object_type: str


@dataclass(frozen=True)
class QueryIssues:
    errors: list[ValidationIssue]
    warnings: list[ValidationIssue]
    #: How many queries the engine checked.
    queries: int


def query_issues(objects: Iterable[QueryObject], *, root: Path | None) -> QueryIssues:
    """Check every query of *objects* and return the findings as issues."""
    from opentide.analysis import EngineUnavailableError, check_queries

    by_path = {item.file_path: item for item in objects}
    try:
        # A file it cannot read is the schema check's `yaml_parse` finding.
        checks = check_queries(by_path, root=root, platforms=None).checks
    except EngineUnavailableError as exc:
        issue = ValidationIssue(
            code=exc.code,
            severity="error",
            message=str(exc),
            suggestion=exc.advice,
            context={"source": ENGINE_SOURCE},
        )
        return QueryIssues(errors=[issue], warnings=[], queries=0)
    errors: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []
    for check in checks:
        owner = by_path[check.file_path]
        for finding in check.findings:
            if finding.severity == "note":
                continue
            issue = ValidationIssue(
                code=finding.code,
                severity=finding.severity,
                object_uuid=owner.uuid,
                object_type=owner.object_type,
                file_path=check.file_path,
                yaml_line=finding.line - 1,
                field_path=finding.field_path or check.field_path,
                message=finding.message,
                suggestion=finding.suggestion,
                context={
                    "source": ENGINE_SOURCE,
                    "language": check.language,
                    "platform": check.platform,
                    "position": {
                        "line": finding.line,
                        "column": finding.column,
                        "end_line": finding.end_line,
                        "end_column": finding.end_column,
                    },
                },
            )
            (errors if finding.severity == "error" else warnings).append(issue)
    return QueryIssues(errors=errors, warnings=warnings, queries=len(checks))
