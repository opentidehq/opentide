"""``end_line`` on every validate and lint finding (#755).

A finding had ``line``, ``column`` and ``end_column`` only, so an editor could
not show a span over several lines (a block-scalar query): ``end_line`` is the
line of the span's last character, with ``end_column`` on it.
"""

from __future__ import annotations

from pathlib import Path

from opentide.analysis import Finding
from opentide.cli.ui import ci, reports
from opentide.cli.ui.diagnostics import (
    DIAGNOSTIC_FIELDS,
    Diagnostic,
    SourceFiles,
    annotate,
    diagnostic_from_engine,
    diagnostic_from_issue,
    diagnostic_from_lint_finding,
)
from opentide.cli.ui.results.base import DiagnosticFields
from opentide.validation.issues import ValidationIssue

#: An ES|QL parse error from line 4 of the file to column 3 of line 6.
_SPANNING = Finding(
    code="esql_parse_error",
    severity="error",
    message="mismatched input",
    line=4,
    column=7,
    end_line=6,
    end_column=3,
    field_path=("configurations", "elastic", "query"),
)
_ONE_LINE = Finding(
    code="kql_unknown_operator",
    severity="error",
    message="unknown tabular operator 'wher'",
    line=9,
    column=5,
    end_line=9,
    end_column=9,
)


def _engine(finding: Finding, tmp_path: Path) -> Diagnostic:
    return diagnostic_from_engine(finding, file_path=tmp_path / "rule.yaml", workspace=tmp_path)


def test_an_engine_finding_keeps_its_end(tmp_path: Path) -> None:
    diagnostic = _engine(_SPANNING, tmp_path)

    fields = diagnostic.fields()
    assert (fields["line"], fields["column"]) == (4, 7)
    assert (fields["end_line"], fields["end_column"]) == (6, 3)
    assert diagnostic.multiline
    # A frame underlines the first line: one character there.
    assert diagnostic.single_line_end == 8


def test_a_one_line_span_ends_on_its_line(tmp_path: Path) -> None:
    diagnostic = _engine(_ONE_LINE, tmp_path)

    assert diagnostic.end_line is None
    assert diagnostic.fields()["end_line"] == 9
    assert diagnostic.fields()["end_column"] == 9
    assert diagnostic.single_line_end == 9
    assert not diagnostic.multiline


def test_a_finding_without_a_line_has_no_end_line() -> None:
    fields = Diagnostic(code="scope_no_match", severity="error", message="x").fields()
    assert fields["line"] is None
    assert fields["end_line"] is None


def test_end_line_is_a_diagnostic_field_of_every_surface() -> None:
    assert DIAGNOSTIC_FIELDS.index("end_line") == DIAGNOSTIC_FIELDS.index("end_column") - 1
    assert set(DIAGNOSTIC_FIELDS) <= set(
        Diagnostic(code="c", severity="error", message="m").fields()
    )
    # The result models every validate and lint document names (opentide --json commands).
    assert "end_line" in DiagnosticFields.model_fields


def test_a_validate_queries_issue_carries_the_engines_end_line(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yaml"
    rule.write_text("name: x\n", encoding="utf-8")
    issue = ValidationIssue(
        code="esql_parse_error",
        severity="error",
        message="mismatched input",
        file_path=rule,
        field_path=["configurations", "elastic", "query"],
        context={"position": {"line": 4, "column": 7, "end_line": 6, "end_column": 3}},
    )
    entry: dict[str, object] = {"code": issue.code}
    diagnostic = diagnostic_from_issue(issue, workspace=tmp_path, sources=SourceFiles())
    annotate(entry, diagnostic)
    assert (entry["line"], entry["end_line"], entry["end_column"]) == (4, 6, 3)


def test_a_validate_schema_issue_ends_on_its_line(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yaml"
    rule.write_text("name: x\nmetadata:\n  tlp: clearr\n", encoding="utf-8")
    issue = ValidationIssue(
        code="vocab_unknown",
        severity="error",
        message="not a TLP value",
        file_path=rule,
        field_path=["metadata", "tlp"],
        context={"value": "clearr", "vocab": "tlp::1.0"},
        yaml_line=2,
    )
    fields = diagnostic_from_issue(issue, workspace=tmp_path, sources=SourceFiles()).fields()
    assert (fields["line"], fields["column"], fields["end_line"], fields["end_column"]) == (
        3,
        8,
        3,
        14,
    )


def test_a_lint_finding_ends_on_its_line_unless_it_says_otherwise(tmp_path: Path) -> None:
    base = {"code": "placeholder", "severity": "warning", "path": "objects/rules/x.yaml"}
    one = diagnostic_from_lint_finding(
        {**base, "line": 3, "column": 2, "end_column": 5}, root=tmp_path, sources=SourceFiles()
    )
    assert one.fields()["end_line"] == 3
    spanning = diagnostic_from_lint_finding(
        {**base, "line": 3, "column": 2, "end_line": 5, "end_column": 4},
        root=tmp_path,
        sources=SourceFiles(),
    )
    assert (spanning.fields()["end_line"], spanning.fields()["end_column"]) == (5, 4)


def test_sarif_regions_span_lines(tmp_path: Path) -> None:
    region = reports._region(_engine(_SPANNING, tmp_path))
    assert region == {"startLine": 4, "endLine": 6, "startColumn": 7, "endColumn": 3}
    assert reports._region(_engine(_ONE_LINE, tmp_path)) == {
        "startLine": 9,
        "startColumn": 5,
        "endColumn": 9,
    }


def test_github_annotations_span_lines_without_an_end_column(tmp_path: Path) -> None:
    spanning = ci.github_annotation(_engine(_SPANNING, tmp_path), root=tmp_path)
    assert "line=4,endLine=6,col=7," in spanning
    assert "endColumn" not in spanning
    one = ci.github_annotation(_engine(_ONE_LINE, tmp_path), root=tmp_path)
    assert "line=9,endLine=9,col=5,endColumn=8," in one


def test_a_span_ending_at_column_one_ends_on_the_line_before(tmp_path: Path) -> None:
    """The engine's end is exclusive: (2, 8)-(3, 1) is the newline at the end of line 2."""
    from opentide.analysis import check_query

    [finding] = [
        item
        for item in check_query("SecurityEvent | where (\n a == 1\n", language="kql")
        if item.severity == "error"
    ]
    assert (finding.line, finding.end_line) == (2, 2)
    assert finding.end_column > finding.column
    diagnostic = _engine(finding, tmp_path)
    assert diagnostic.fields()["end_line"] == 2
    assert not diagnostic.multiline
    annotation = ci.github_annotation(diagnostic, root=tmp_path)
    assert "endLine" not in annotation or "endLine=2" in annotation
    assert "endLine=3" not in annotation


def test_a_longer_span_ending_at_column_one_ends_after_the_previous_line() -> None:
    from opentide.analysis import _span_end

    text = "a = (\n  b,\n  c\nd"
    # Line 1 column 5 to line 4 column 1: the last character is line 3's newline.
    assert _span_end(1, 5, 4, 1, text) == (3, 4)
    assert _span_end(1, 5, 4, 1, text.replace("\n", "\r\n")) == (3, 4)
    # Without the text, a span onto the next line still collapses to one line.
    assert _span_end(2, 8, 3, 1, None) == (2, 9)
    # Any other end is left as the engine gave it.
    assert _span_end(4, 7, 6, 3, text) == (6, 3)
    assert _span_end(2, 1, 2, 1, text) == (2, 1)
