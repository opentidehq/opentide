"""Findings as report files: SARIF 2.1.0 for code scanning, Code Climate JSON for GitLab.

``opentide validate --format sarif`` and ``opentide lint --format codequality``
build their document here from the same :class:`Diagnostic` list the code
frames print. SARIF rules come from the ``opentide explain`` pages, so each
alert links to what the code means and how to fix it.

Paths are relative to the repository (the CI checkout when known, else the
workspace). A finding that names no file is left out of both reports: GitHub
code scanning and GitLab Code Quality both need a file. The job log and the
summary still carry it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Sequence
from enum import Enum
from typing import Any

from opentide.cli.ui.diagnostics import Diagnostic
from opentide.cli.ui.summary import DIAGNOSTICS_DOCS_URL, explain_url

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

#: GitLab Code Quality severities: ``info``, ``minor``, ``major``, ``critical``, ``blocker``.
CODEQUALITY_SEVERITY = {"error": "major", "warning": "minor", "note": "info"}

_PAGE_SEVERITY = re.compile(r"^Severity: (error|warning|note)\b", re.MULTILINE)


class ReportFormat(str, Enum):
    """``--format``: the code frames people read, or a report file for a CI service."""

    text = "text"
    sarif = "sarif"
    codequality = "codequality"

    def __str__(self) -> str:
        return self.value


#: Gives the path to report a diagnostic under, or ``None`` when it names no file.
PathFor = Callable[[Diagnostic], "str | None"]


def _own_path(diagnostic: Diagnostic) -> str | None:
    return diagnostic.path


def _fingerprint(diagnostic: Diagnostic, path: str, seen: dict[str, int]) -> str:
    """Stable across runs and line moves; repeated findings get their occurrence number."""
    key = "\x1f".join([diagnostic.code, path, "/".join(diagnostic.field_path), diagnostic.message])
    occurrence = seen.get(key, 0)
    seen[key] = occurrence + 1
    return hashlib.sha256(f"{key}\x1f{occurrence}".encode()).hexdigest()


# --------------------------------------------------------------------------
# SARIF 2.1.0
# --------------------------------------------------------------------------


def _rule_name(code: str) -> str:
    return "".join(part.capitalize() for part in code.split("_"))


def sarif_rule(code: str) -> dict[str, Any]:
    """A ``reportingDescriptor`` built from the ``opentide explain`` page for *code*."""
    from opentide.cli.services.explain import load_page

    page = load_page(code)
    rule: dict[str, Any] = {"id": code, "name": _rule_name(code), "helpUri": explain_url(code)}
    if page is None:
        return rule
    rule["shortDescription"] = {"text": page.summary}
    rule["fullDescription"] = {"text": page.summary}
    rule["help"] = {"text": page.markdown, "markdown": page.markdown}
    if found := _PAGE_SEVERITY.search(page.markdown):
        rule["defaultConfiguration"] = {"level": found.group(1)}
    return rule


def _region(diagnostic: Diagnostic) -> dict[str, int] | None:
    if diagnostic.line is None:
        return None
    region = {"startLine": diagnostic.line}
    if diagnostic.column is not None:
        region["startColumn"] = diagnostic.column
        if diagnostic.end_column is not None and diagnostic.end_column > diagnostic.column:
            # SARIF's endColumn is exclusive, like ours.
            region["endColumn"] = diagnostic.end_column
    return region


def _sarif_fixes(diagnostic: Diagnostic, path: str) -> list[dict[str, Any]]:
    if diagnostic.fix is None or not diagnostic.fix.edits:
        return []
    replacements = [
        {
            "deletedRegion": {
                "startLine": edit.line,
                "startColumn": edit.column,
                "endColumn": edit.end_column,
            },
            "insertedContent": {"text": edit.replacement},
        }
        for edit in diagnostic.fix.edits
    ]
    values = ", ".join(repr(edit.replacement) for edit in diagnostic.fix.edits)
    description = f"Replace with {values}"
    if diagnostic.fix.safe:
        description += " (safe to apply without review)"
    return [
        {
            "description": {"text": description},
            "artifactChanges": [{"artifactLocation": {"uri": path}, "replacements": replacements}],
        }
    ]


def sarif_report(
    diagnostics: Sequence[Diagnostic],
    *,
    command: str,
    version: str,
    path_for: PathFor = _own_path,
) -> dict[str, Any]:
    """One SARIF 2.1.0 log with one run of opentide *command*.

    The driver lists a rule for every ``opentide explain`` page, plus any
    code a finding carries that has none. ``automationDetails.id`` is
    ``opentide/<command>/``, so GitHub keeps the alerts of ``validate`` and
    ``lint`` apart.
    """
    from opentide.cli.services.explain import diagnostic_codes

    codes = list(diagnostic_codes())
    codes.extend(sorted({item.code for item in diagnostics} - set(codes)))
    index = {code: position for position, code in enumerate(codes)}
    results: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    for diagnostic in diagnostics:
        path = path_for(diagnostic)
        if path is None:
            continue
        location: dict[str, Any] = {"artifactLocation": {"uri": path}}
        region = _region(diagnostic)
        if region is not None:
            location["region"] = region
        text = diagnostic.message + (f"\nhelp: {diagnostic.help}" if diagnostic.help else "")
        result: dict[str, Any] = {
            "ruleId": diagnostic.code,
            "ruleIndex": index[diagnostic.code],
            "level": diagnostic.severity,
            "message": {"text": text},
            "locations": [{"physicalLocation": location}],
            "partialFingerprints": {"opentide/v1": _fingerprint(diagnostic, path, seen)},
        }
        if fixes := _sarif_fixes(diagnostic, path):
            result["fixes"] = fixes
        results.append(result)
    slug = "-".join(command.split())
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "opentide",
                        "version": version,
                        "informationUri": DIAGNOSTICS_DOCS_URL,
                        "rules": [sarif_rule(code) for code in codes],
                    }
                },
                "automationDetails": {"id": f"opentide/{slug}/"},
                "columnKind": "unicodeCodePoints",
                "results": results,
            }
        ],
    }


# --------------------------------------------------------------------------
# GitLab Code Quality (a subset of Code Climate)
# --------------------------------------------------------------------------


def codequality_report(
    diagnostics: Sequence[Diagnostic], *, path_for: PathFor = _own_path
) -> list[dict[str, Any]]:
    """The array GitLab reads from ``artifacts:reports:codequality``."""
    issues: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    for diagnostic in diagnostics:
        path = path_for(diagnostic)
        if path is None:
            continue
        description = diagnostic.message
        if diagnostic.help:
            description += f" (help: {diagnostic.help})"
        issue: dict[str, Any] = {
            "type": "issue",
            "check_name": diagnostic.code,
            "description": description,
            "categories": ["Bug Risk"] if diagnostic.severity == "error" else ["Style"],
            "severity": CODEQUALITY_SEVERITY[diagnostic.severity],
            "fingerprint": _fingerprint(diagnostic, path, seen),
            "location": {"path": path, "lines": {"begin": diagnostic.line or 1}},
        }
        issues.append(issue)
    return issues


def build_report(
    report_format: ReportFormat,
    diagnostics: Sequence[Diagnostic],
    *,
    command: str,
    version: str,
    path_for: PathFor = _own_path,
) -> Any:
    """The document for *report_format*; ``text`` has none."""
    if report_format is ReportFormat.sarif:
        return sarif_report(diagnostics, command=command, version=version, path_for=path_for)
    if report_format is ReportFormat.codequality:
        return codequality_report(diagnostics, path_for=path_for)
    raise ValueError(f"{report_format} is not a report format")

