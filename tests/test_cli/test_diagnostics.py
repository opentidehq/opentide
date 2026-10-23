"""Diagnostics: positions read from the file, fixes, JSON fields and code frames."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
import yaml
from rich.console import Console

from opentide.cli.ui import Diagnostic, render_diagnostics
from opentide.cli.ui.codeframe import display_path, link_url
from opentide.cli.ui.diagnostics import (
    DIAGNOSTIC_FIELDS,
    Fix,
    SourceFiles,
    TextEdit,
    annotate,
    diagnostic_from_issue,
    diagnostic_from_lint_finding,
    relative_path,
)
from opentide.cli.ui.mode import OutputMode
from opentide.core.io import DuplicateKeyError, describe_yaml_error, parse_yaml
from opentide.validation.errors import merge_reference_findings
from opentide.validation.issues import ValidationIssue, ValidationReport

RULE = """\
name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clearr
  author: Tutorial Author
techniques: [T1059, T9999]
detection_model: 00000000-0000-4000-8002-DEADBEEF0000   # the objective from step 4
description: 'it''s quoted'
configurations:
  sentinel:
    enabled: true
"""
BROKEN = RULE.replace("  tlp: clearr\n", "  tlp: [clear\n")
UUID = "00000000-0000-4000-8003-000000000001"
DANGLING = "00000000-0000-4000-8002-DEADBEEF0000"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    rules = tmp_path / "objects" / "rules"
    rules.mkdir(parents=True)
    (rules / "sentinel-kql-rule.yaml").write_text(RULE, encoding="utf-8")
    (rules / "broken.yaml").write_text(BROKEN, encoding="utf-8")
    return tmp_path


def _rule(workspace: Path, name: str = "sentinel-kql-rule.yaml") -> Path:
    return workspace / "objects" / "rules" / name


def _typo(workspace: Path) -> ValidationIssue:
    return ValidationIssue(
        code="vocab_unknown",
        object_uuid=UUID,
        object_type="rule",
        file_path=_rule(workspace),
        yaml_line=6,
        field_path=("metadata", "tlp"),
        message="Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry",
        suggestion="clear",
        context={"vocab": "tlp::1.0", "value": "clearr"},
    )


def _dangling(workspace: Path) -> ValidationIssue:
    return ValidationIssue(
        code="invalid_ref",
        object_uuid=UUID,
        object_type="rule",
        file_path=_rule(workspace),
        yaml_line=9,
        field_path=("detection_model",),
        message=f"Unknown objective or signal reference {DANGLING!r}",
        context={"value": DANGLING},
    )


def _syntax(workspace: Path) -> ValidationIssue:
    path = _rule(workspace, "broken.yaml")
    try:
        parse_yaml(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        message = f"Could not parse object YAML: {describe_yaml_error(exc).message}"
    return ValidationIssue(code="yaml_parse", object_type="rule", file_path=path, message=message)


# --------------------------------------------------------------------------
# YAML problems
# --------------------------------------------------------------------------


def test_a_yaml_problem_names_its_position_not_the_stream() -> None:
    with pytest.raises(yaml.YAMLError) as caught:
        parse_yaml(BROKEN)
    problem = describe_yaml_error(caught.value)
    assert (problem.line, problem.column) == (8, 9)
    assert problem.message == (
        "did not find expected ',' or ']' at line 8, column 9 "
        "(while parsing a flow sequence that starts at line 7, column 8)"
    )
    assert "<unicode string>" not in problem.message


def test_a_duplicate_key_keeps_its_message_and_gains_a_position() -> None:
    with pytest.raises(DuplicateKeyError) as caught:
        parse_yaml("name: one\nname: two\n")
    assert str(caught.value) == "duplicate key 'name' at line 2"
    assert describe_yaml_error(caught.value).message == "duplicate key 'name' at line 2, column 1"


def test_a_non_yaml_error_is_described_by_its_first_line() -> None:
    problem = describe_yaml_error(OSError("disk on fire\nsecond line"))
    assert (problem.message, problem.line) == ("disk on fire", None)


# --------------------------------------------------------------------------
# Positions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field_path", "value", "expected"),
    [
        (("metadata", "tlp"), None, (7, 8, 14, "clearr")),
        (("techniques",), "T9999", (9, 21, 26, "T9999")),
        (("techniques", "0"), None, (9, 14, 19, "T1059")),
        (("detection_model",), None, (10, 18, 54, DANGLING)),
        (("description",), None, (11, 15, 27, "it''s quoted")),
        # A block points at its key; a missing key at the mapping it belongs in.
        (("configurations", "sentinel"), None, (13, 3, 11, "sentinel")),
        (("metadata", "missing"), None, (2, 1, 9, "metadata")),
    ],
)
def test_span_reads_the_value_from_the_file(
    workspace: Path, field_path: tuple[str, ...], value: str | None, expected: tuple
) -> None:
    span = SourceFiles().span(_rule(workspace), field_path, value)
    assert span is not None
    assert (span.line, span.column, span.end_column, span.text)[: len(expected)] == expected


def test_span_is_none_without_a_document(workspace: Path) -> None:
    sources = SourceFiles()
    assert sources.span(_rule(workspace, "broken.yaml"), ("metadata",)) is None
    assert sources.span(workspace / "absent.yaml", ("metadata",)) is None
    assert sources.span(_rule(workspace), ()) is None
    assert sources.span(_rule(workspace), ("absent",)) is None


def test_relative_path_falls_back_to_the_absolute_path(tmp_path: Path) -> None:
    assert relative_path(tmp_path / "a" / "b.yaml", tmp_path) == "a/b.yaml"
    assert relative_path(tmp_path / "b.yaml", tmp_path / "elsewhere") == (
        (tmp_path / "b.yaml").as_posix()
    )
    assert relative_path(tmp_path / "b.yaml", None) == (tmp_path / "b.yaml").as_posix()


# --------------------------------------------------------------------------
# Adapters
# --------------------------------------------------------------------------


def test_a_vocabulary_typo_carries_a_safe_fix(workspace: Path) -> None:
    diagnostic = diagnostic_from_issue(_typo(workspace), workspace=workspace, sources=SourceFiles())
    assert diagnostic.path == "objects/rules/sentinel-kql-rule.yaml"
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (7, 8, 14)
    assert diagnostic.help == "did you mean 'clear'?"
    assert diagnostic.fix == Fix(True, (TextEdit(7, 8, 14, "clear"),))
    assert diagnostic.label == "not in tlp::1.0"
    assert diagnostic.explain == "opentide explain vocab_unknown"


def test_a_distant_suggestion_is_not_safe(workspace: Path) -> None:
    issue = _typo(workspace).model_copy(update={"suggestion": "red"})
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.fix is not None and diagnostic.fix.safe is False


def test_a_reference_suggestion_is_never_safe(workspace: Path) -> None:
    issue = _dangling(workspace).model_copy(
        update={"suggestion": "00000000-0000-4000-8002-000000000001"}
    )
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.fix is not None and diagnostic.fix.safe is False


def test_a_dangling_reference_names_the_listing(workspace: Path) -> None:
    diagnostic = diagnostic_from_issue(
        _dangling(workspace), workspace=workspace, sources=SourceFiles()
    )
    assert diagnostic.help == "opentide info objectives lists the ones that exist"
    assert diagnostic.fix is None
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (10, 18, 54)


def test_no_fix_when_the_file_says_something_else(workspace: Path) -> None:
    issue = _typo(workspace).model_copy(update={"context": {"value": "other"}})
    assert diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles()).fix is None


def test_a_yaml_parse_issue_points_at_the_parser_position(workspace: Path) -> None:
    diagnostic = diagnostic_from_issue(
        _syntax(workspace), workspace=workspace, sources=SourceFiles()
    )
    assert diagnostic.message == "Could not parse object YAML: did not find expected ',' or ']'"
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (8, 9, 10)
    assert diagnostic.notes == (
        ("note", "while parsing a flow sequence that starts at line 7, column 8"),
    )


def test_an_issue_without_a_file_has_no_position() -> None:
    issue = ValidationIssue(code="scope_no_match", message="--file 'x' matched no object")
    diagnostic = diagnostic_from_issue(issue, workspace=None, sources=SourceFiles())
    assert (diagnostic.path, diagnostic.line, diagnostic.column) == (None, None, None)
    assert diagnostic.fields()["explain"] == "opentide explain scope_no_match"


def test_a_configuration_enum_lists_what_is_expected(workspace: Path) -> None:
    issue = ValidationIssue(
        code="config_enum_unknown",
        message="Value 'Night' is not a configured responders value.",
        context={"setting": "responders", "value": "Night", "allowed": ["SOC", "CERT"]},
    )
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.notes == (("expected", "one of SOC, CERT"),)
    assert diagnostic.label == "not a configured responders value"


def test_a_warning_stays_a_warning(workspace: Path) -> None:
    issue = ValidationIssue(
        code="platform_not_enabled",
        severity="warning",
        file_path=_rule(workspace),
        yaml_line=13,
        field_path=("configurations", "sentinel"),
        message="this block will not deploy",
    )
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.severity == "warning"
    assert (diagnostic.line, diagnostic.column) == (13, 3)


def test_annotate_adds_fields_and_keeps_every_existing_key(workspace: Path) -> None:
    report = ValidationReport(ok=False, issues=[_typo(workspace)])
    (entry,) = report.model_dump_json_ready()["issues"]
    before = dict(entry)
    diagnostic = diagnostic_from_issue(_typo(workspace), workspace=workspace, sources=SourceFiles())
    annotate(entry, diagnostic)
    assert {key: entry[key] for key in before} == before
    assert list(entry)[len(before) :] == list(DIAGNOSTIC_FIELDS)
    assert entry["yaml_line"] == 6 and entry["line"] == 7
    assert entry["fix"] == {
        "safe": True,
        "edits": [{"line": 7, "column": 8, "end_column": 14, "replacement": "clear"}],
    }


def test_to_dict_is_the_whole_diagnostic() -> None:
    diagnostic = Diagnostic(code="yaml_parse", severity="error", message="bad", field_path=("a",))
    assert diagnostic.to_dict() == {
        "code": "yaml_parse",
        "severity": "error",
        "message": "bad",
        "field_path": ["a"],
        "path": None,
        "line": None,
        "column": None,
        "end_column": None,
        "help": None,
        "fix": None,
        "explain": "opentide explain yaml_parse",
    }


def test_a_lint_finding_points_at_its_key(workspace: Path) -> None:
    finding = {
        "check": "metadata",
        "severity": "info",
        "path": "objects/rules/sentinel-kql-rule.yaml",
        "yaml_line": 1,
        "message": "Recommended metadata missing: organisation",
        "code": "metadata_recommended",
        "field_path": ["metadata"],
    }
    diagnostic = diagnostic_from_lint_finding(finding, root=workspace, sources=SourceFiles())
    assert diagnostic.severity == "note"
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (2, 1, 9)


# --------------------------------------------------------------------------
# One finding per cause
# --------------------------------------------------------------------------


def test_a_dangling_reference_is_reported_once(workspace: Path) -> None:
    vocab = ValidationIssue(
        code="vocab_unknown",
        object_uuid=UUID,
        field_path=("detection_model",),
        message=f"Value {DANGLING!r} is not a valid 'objective' vocabulary entry",
        suggestion="00000000-0000-4000-8002-000000000001",
        context={"vocab": "objective", "value": DANGLING},
    )
    other = _typo(workspace)
    merged = merge_reference_findings([vocab, other, _dangling(workspace), _dangling(workspace)])
    assert [issue.code for issue in merged] == ["vocab_unknown", "invalid_ref"]
    assert merged[0] is other
    assert merged[1].suggestion == "00000000-0000-4000-8002-000000000001"


def test_a_vocabulary_finding_on_another_value_stays(workspace: Path) -> None:
    vocab = ValidationIssue(
        code="vocab_unknown",
        object_uuid=UUID,
        field_path=("detection_model",),
        message="other",
        context={"value": "something-else"},
    )
    assert merge_reference_findings([vocab, _dangling(workspace)]) == [vocab, _dangling(workspace)]


def test_nothing_to_merge_returns_the_list() -> None:
    issues = [ValidationIssue(code="schema_validation", message="bad")]
    assert merge_reference_findings(issues) is issues


# --------------------------------------------------------------------------
# Code frames
# --------------------------------------------------------------------------


class _Stream(io.StringIO):
    def __init__(self, encoding: str) -> None:
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._encoding


def _console(*, human: bool, encoding: str = "utf-8") -> Console:
    stream = _Stream(encoding)
    return Console(
        record=True,
        width=72,
        file=stream,
        force_terminal=human,
        color_system="standard" if human else None,
    )


@pytest.mark.parametrize("case", ["enum-typo", "dangling-reference", "yaml-syntax"])
@pytest.mark.parametrize("mode", [OutputMode.HUMAN, OutputMode.PLAIN])
def test_code_frame_snapshot(
    workspace: Path, case: str, mode: OutputMode, snapshot, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENTIDE_LINKS", "none")
    issue = {"enum-typo": _typo, "dangling-reference": _dangling, "yaml-syntax": _syntax}[case]
    sources = SourceFiles()
    diagnostic = diagnostic_from_issue(issue(workspace), workspace=workspace, sources=sources)
    human = mode is OutputMode.HUMAN
    console = _console(human=human)
    render_diagnostics(console, [diagnostic], sources=sources, mode=mode, cwd=workspace)
    assert console.export_text(styles=human) == snapshot


def test_frames_are_grouped_by_file_and_ordered_by_line(workspace: Path) -> None:
    sources = SourceFiles()
    diagnostics = [
        diagnostic_from_issue(issue, workspace=workspace, sources=sources)
        for issue in (_dangling(workspace), _syntax(workspace), _typo(workspace))
    ]
    diagnostics.append(Diagnostic(code="scope_no_match", severity="error", message="nothing"))
    console = _console(human=False)
    render_diagnostics(console, diagnostics, sources=sources, mode=OutputMode.PLAIN, cwd=workspace)
    headers = [line for line in console.export_text().splitlines() if line.startswith("error[")]
    assert [line.split("]")[0] for line in headers] == [
        "error[yaml_parse",
        "error[vocab_unknown",
        "error[invalid_ref",
        "error[scope_no_match",
    ]


def test_quiet_keeps_errors_only(workspace: Path) -> None:
    warning = Diagnostic(code="platform_not_enabled", severity="warning", message="w")
    error = Diagnostic(code="scope_no_match", severity="error", message="e")
    console = _console(human=False)
    render_diagnostics(console, [warning, error], mode=OutputMode.PLAIN, quiet=True)
    assert console.export_text() == "error[scope_no_match]: e\n\n"


def test_a_location_without_source_closes_the_frame(workspace: Path) -> None:
    diagnostic = Diagnostic(
        code="filename_mismatch",
        severity="warning",
        message="Filename does not match",
        path="objects/rules/x.yaml",
        file_path=workspace / "objects/rules/x.yaml",
    )
    console = _console(human=False)
    render_diagnostics(console, [diagnostic], mode=OutputMode.PLAIN, cwd=workspace)
    assert console.export_text() == (
        "warning[filename_mismatch]: Filename does not match\n  ╰─▶ objects/rules/x.yaml\n\n"
    )


def test_an_ascii_stream_gets_ascii_frames(workspace: Path) -> None:
    sources = SourceFiles()
    diagnostic = diagnostic_from_issue(_typo(workspace), workspace=workspace, sources=sources)
    console = _console(human=False, encoding="ascii")
    render_diagnostics(console, [diagnostic], sources=sources, mode=OutputMode.PLAIN, cwd=workspace)
    text = console.export_text()
    assert "--> objects/rules/sentinel-kql-rule.yaml:7:8" in text
    assert "  |        ^^^^^^ not in tlp::1.0" in text
    text.encode("ascii")


def test_a_fix_without_help_is_spelled_out(workspace: Path) -> None:
    diagnostic = Diagnostic(
        code="vocab_unknown",
        severity="error",
        message="m",
        fix=Fix(True, (TextEdit(1, 1, 2, "clear"),)),
    )
    console = _console(human=False)
    render_diagnostics(console, [diagnostic], mode=OutputMode.PLAIN)
    assert "╰─ fix: replace with 'clear'" in console.export_text()


def test_display_path_is_relative_to_the_current_directory_inside_it(workspace: Path) -> None:
    diagnostic = diagnostic_from_issue(_typo(workspace), workspace=workspace, sources=SourceFiles())
    assert display_path(diagnostic, workspace / "objects") == "rules/sentinel-kql-rule.yaml"
    assert display_path(diagnostic, workspace.parent / "elsewhere") == diagnostic.path


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, "file:///w/rule.yaml"),
        ({"TERM_PROGRAM": "vscode"}, "vscode://file/w/rule.yaml:8:3"),
        ({"TERM_PROGRAM": "vscode", "OPENTIDE_LINKS": "cursor"}, "cursor://file/w/rule.yaml:8:3"),
        ({"TERM_PROGRAM": "vscode", "OPENTIDE_LINKS": "file"}, "file:///w/rule.yaml"),
        ({"OPENTIDE_LINKS": "none"}, None),
    ],
)
@pytest.mark.skipif(__import__("os").name == "nt", reason="POSIX paths")
def test_link_url_follows_the_editor(env: dict[str, str], expected: str | None) -> None:
    assert link_url(Path("/w/rule.yaml"), 8, 3, env) == expected


def test_human_mode_links_the_location(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_LINKS", raising=False)
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    sources = SourceFiles()
    diagnostic = diagnostic_from_issue(_typo(workspace), workspace=workspace, sources=sources)
    console = Console(file=io.StringIO(), force_terminal=True, width=72)
    render_diagnostics(console, [diagnostic], sources=sources, mode=OutputMode.HUMAN)
    assert "\x1b]8;" in console.file.getvalue()  # type: ignore[attr-defined]
