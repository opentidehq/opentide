"""The ``queries`` check: every query an object carries, through the analysis engine.

One of ``opentide validate``'s default checks (``--check queries`` alone,
``--queries off`` skips it). Each query is checked in its own language with
its platform's profile (Sentinel or Defender KQL, SPL, the Elastic languages,
Carbon Black Lucene), offline. The engine's errors (a query the platform
would reject) become validation issues at the place in the file the engine
names; ``--queries warn`` reports them as warnings. Its warnings and notes
are style, which ``opentide lint`` reports (its ``queries`` check). A query
``opentide new`` wrote as a placeholder is skipped: it is lint's
``placeholders`` finding, and a draft must still validate.

A missing engine is an ``engine_unavailable`` error, whatever the mode: the
check never skips.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from opentide.validation.issues import ValidationIssue

if TYPE_CHECKING:
    from opentide.analysis import QueryCheck

#: ``ValidationIssue.context["source"]`` of the issues this check reports.
ENGINE_SOURCE = "engine"


@dataclass(frozen=True)
class QueryObject:
    """An object file whose queries the check reads."""

    file_path: Path
    uuid: str
    object_type: str


#: ``ValidationIssue.context`` key marking an error ``--queries warn`` reports as a warning.
REPORTED_AS_WARNING = "reported_as_warning"
#: The comment ``opentide new`` writes after a value it invented.
_PLACEHOLDER = re.compile(r"\s#\s*opentide:placeholder\s*$")


@dataclass(frozen=True)
class QueryIssues:
    errors: list[ValidationIssue]
    warnings: list[ValidationIssue]
    #: How many queries the engine checked.
    queries: int


def query_issues(
    objects: Iterable[QueryObject], *, root: Path | None, as_warnings: bool = False
) -> QueryIssues:
    """Check every query of *objects* and return the engine's errors as issues.

    With *as_warnings* they are warnings, marked :data:`REPORTED_AS_WARNING`.
    """
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
    lines: dict[Path, list[str]] = {}
    checked = 0
    for check in checks:
        owner = by_path[check.file_path]
        if is_placeholder_query(check, lines):
            continue
        checked += 1
        for finding in check.findings:
            if finding.severity != "error":
                continue  # style: opentide lint's queries check
            context: dict[str, object] = {
                "source": ENGINE_SOURCE,
                "language": check.language,
                "platform": check.platform,
                "position": {
                    "line": finding.line,
                    "column": finding.column,
                    "end_line": finding.end_line,
                    "end_column": finding.end_column,
                },
            }
            if as_warnings:
                context[REPORTED_AS_WARNING] = True
            issue = ValidationIssue(
                code=finding.code,
                severity="warning" if as_warnings else "error",
                object_uuid=owner.uuid,
                object_type=owner.object_type,
                file_path=check.file_path,
                yaml_line=finding.line - 1,
                field_path=finding.field_path or check.field_path,
                message=finding.message,
                suggestion=finding.suggestion,
                context=context,
            )
            (warnings if as_warnings else errors).append(issue)
    return QueryIssues(errors=errors, warnings=warnings, queries=checked)


def is_placeholder_query(check: QueryCheck, lines: dict[Path, list[str]]) -> bool:
    """Whether the query is still the stand-in ``opentide new`` wrote.

    Its key carries the marker, on the query's first line (``query: ...``) or
    the line above it (``query: |``), and its text is still ``...``: a query
    written under a marker someone forgot to delete is checked. *lines*
    caches each file's lines.
    """
    if check.file_path not in lines:
        try:
            lines[check.file_path] = check.file_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            lines[check.file_path] = []
    text = lines[check.file_path]
    if not 0 < check.line <= len(text):
        return False
    marked = any(
        0 <= index < len(text) and _PLACEHOLDER.search(text[index])
        for index in (check.line - 1, check.line - 2)
    )
    return marked and is_stand_in(text[check.line - 1][check.column - 1 :])


def is_stand_in(line: str) -> bool:
    """Whether *line*, from a value's start, is the ``...`` stand-in ``opentide new`` writes."""
    return _PLACEHOLDER.sub("", line).strip() == STAND_IN


#: The free-text stand-in ``opentide new`` writes, a query included.
STAND_IN = "..."
