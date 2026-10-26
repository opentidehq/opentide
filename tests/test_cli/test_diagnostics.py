"""Diagnostics: positions read from the file, fixes, JSON fields and code frames."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
import yaml
from rich.cells import cell_len
from rich.console import Console

from opentide.cli.ui import Diagnostic, render_diagnostics
from opentide.cli.ui.codeframe import display_path, link_url, underline_offset
from opentide.cli.ui.diagnostics import (
    DIAGNOSTIC_FIELDS,
    Fix,
    SourceFiles,
    TextEdit,
    annotate,
    diagnostic_from_issue,
    diagnostic_from_lint_finding,
    diagnostics_from_issues,
    is_safe_replacement,
    relative_path,
    split_yaml_lines,
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


def test_a_duplicate_key_is_underlined_whole(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text("name: one\nnamee: a\nnamee: b\n", encoding="utf-8")
    issue = ValidationIssue(code="yaml_parse", file_path=path, message="x")
    diagnostic = diagnostic_from_issue(issue, workspace=tmp_path, sources=SourceFiles())
    assert diagnostic.message == "Could not parse object YAML: duplicate key 'namee'"
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (3, 1, 6)


def test_a_second_document_reads_as_one_sentence() -> None:
    with pytest.raises(yaml.YAMLError) as caught:
        parse_yaml("a: 1\n---\nb: 2\n")
    assert describe_yaml_error(caught.value).message == (
        "expected a single document in the stream, but found another document at line 2, column 1"
    )


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


def test_lines_break_where_yaml_breaks_them(tmp_path: Path) -> None:
    """U+2028 inside a quoted scalar is not a line break for YAML, nor for the frame."""
    path = tmp_path / "rule.yaml"
    path.write_text('name: "Sentinel\u2028KQL Rule"\r\nmetadata:\r\n  tlp: clearr\r\n', "utf-8")
    sources = SourceFiles()
    assert sources.line(path, 3) == "  tlp: clearr"
    span = sources.span(path, ("metadata", "tlp"))
    assert span is not None and (span.line, span.column, span.end_column) == (3, 8, 14)
    assert split_yaml_lines("a\rb\n\nc\n") == ["a", "b", "", "c"]


def test_a_missing_field_names_itself(workspace: Path) -> None:
    issue = ValidationIssue(
        code="schema_validation",
        file_path=_rule(workspace),
        field_path=("configurations", "sentinel", "status"),
        message="Field required",
    )
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.message == "missing required field 'status' in configurations.sentinel"
    assert diagnostic.label == "add 'status' under this key"
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (13, 3, 11)


def test_an_extra_key_is_underlined_at_the_key(workspace: Path) -> None:
    issue = ValidationIssue(
        code="schema_validation",
        file_path=_rule(workspace),
        field_path=("metadata", "author"),
        message="Extra inputs are not permitted",
    )
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.message == "metadata.author: Extra inputs are not permitted"
    assert diagnostic.label is None
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (8, 3, 9)


def test_span_is_none_without_a_document(workspace: Path) -> None:
    sources = SourceFiles()
    assert sources.span(_rule(workspace, "broken.yaml"), ("metadata",)) is None
    assert sources.span(workspace / "absent.yaml", ("metadata",)) is None
    assert sources.span(_rule(workspace), ()) is None


def test_a_missing_top_level_key_spans_the_first_key(workspace: Path) -> None:
    """The top-level mapping has no key of its own: its first key stands for it."""
    span = SourceFiles().span(_rule(workspace), ("absent",))
    assert span is not None and not span.found
    assert (span.line, span.column, span.end_column, span.text) == (1, 1, 5, "name")


def test_relative_path_falls_back_to_the_absolute_path(tmp_path: Path) -> None:
    assert relative_path(tmp_path / "a" / "b.yaml", tmp_path) == "a/b.yaml"
    assert relative_path(tmp_path / "b.yaml", tmp_path / "elsewhere") == (
        (tmp_path / "b.yaml").as_posix()
    )
    assert relative_path(tmp_path / "b.yaml", None) == (tmp_path / "b.yaml").as_posix()


# --------------------------------------------------------------------------
# Adapters
# --------------------------------------------------------------------------


def test_a_vocabulary_typo_carries_a_fix_for_review(workspace: Path) -> None:
    diagnostic = diagnostic_from_issue(_typo(workspace), workspace=workspace, sources=SourceFiles())
    assert diagnostic.path == "objects/rules/sentinel-kql-rule.yaml"
    assert diagnostic.object_uuid == UUID
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (7, 8, 14)
    assert diagnostic.help == "did you mean 'clear'?"
    # 'clearr' and 'clear' are different words: a person or an agent decides.
    assert diagnostic.fix == Fix(False, (TextEdit(7, 8, 14, "clear"),))
    assert diagnostic.label == "not in tlp::1.0"
    assert diagnostic.explain == "opentide explain vocab_unknown"


@pytest.mark.parametrize(
    ("code", "value", "suggestion", "safe"),
    [
        # Identifiers: one changed character is another technique, not a typo.
        ("vocab_unknown", "T1O59", "T1659", False),
        ("vocab_unknown", "T1059.099", "T1059.009", False),
        ("vocab_unknown", "t1059", "T1059", False),
        ("vocab_unknown", "clearr", "clear", False),
        ("vocab_unknown", "red", "amber", False),
        ("vocab_unknown", "amber strict", "amber+strict", False),
        # The same word, spelled differently.
        ("vocab_unknown", "CLEAR", "clear", True),
        ("vocab_unknown", "credential_access", "Credential Access", True),
        ("chaining_relation_unknown", "Preceeds", "preceeds", True),
        ("invalid_ref", "Credential Access", "credential access", False),
        ("vocab_unknown", "clear", "clear", False),
    ],
)
def test_only_a_respelling_is_safe(code: str, value: str, suggestion: str, safe: bool) -> None:
    assert is_safe_replacement(code, value, suggestion) is safe


def test_an_attack_typo_is_emitted_but_not_safe(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yaml"
    rule.write_text("techniques: [T1059, T1059.099, 'T1O59']\n", encoding="utf-8")
    sources = SourceFiles()
    for value, suggestion, columns in (
        ("T1059.099", "T1059.009", (21, 30)),
        ("T1O59", "T1659", (33, 38)),
    ):
        issue = ValidationIssue(
            code="vocab_unknown",
            file_path=rule,
            field_path=("techniques",),
            message=f"Value {value!r} is not a valid 'att&ck' vocabulary entry",
            suggestion=suggestion,
            context={"vocab": "att&ck", "value": value},
        )
        fix = diagnostic_from_issue(issue, workspace=tmp_path, sources=sources).fix
        assert fix == Fix(False, (TextEdit(1, *columns, suggestion),)), value


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


@pytest.mark.parametrize("code", ["invalid_uuid", "missing_uuid", "duplicate_id"])
def test_a_uuid_finding_closes_its_frame_with_a_step(workspace: Path, code: str) -> None:
    """The engine gives these codes no suggestion; the frame still ends in ``╰─ help:``."""
    issue = ValidationIssue(
        code=code,
        object_uuid=UUID,
        object_type="rule",
        file_path=_rule(workspace),
        yaml_line=2,
        field_path=("metadata", "uuid"),
        message="UUID 'x' is not a valid UUIDv4",
    )
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.help and "UUID v4" in diagnostic.help
    console = Console(file=io.StringIO(), width=120, color_system=None)
    render_diagnostics(console, [diagnostic], mode=OutputMode.PLAIN, cwd=workspace)
    lines = console.file.getvalue().rstrip("\n").splitlines()
    assert lines[-1].lstrip().startswith("╰─ help: ")


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
    assert diagnostic.label == "not in [[responders]]"
    assert diagnostic.message == "'Night' is not a configured responder"


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
        "safe": False,
        "edits": [
            {"line": 7, "column": 8, "end_line": 7, "end_column": 14, "replacement": "clear"}
        ],
    }


def test_a_text_edit_may_span_lines() -> None:
    assert TextEdit(3, 1, 5, "x", end_line=4).to_dict() == {
        "line": 3,
        "column": 1,
        "end_line": 4,
        "end_column": 5,
        "replacement": "x",
    }


def test_to_dict_is_the_whole_diagnostic() -> None:
    diagnostic = Diagnostic(code="yaml_parse", severity="error", message="bad", field_path=("a",))
    assert diagnostic.to_dict() == {
        "code": "yaml_parse",
        "severity": "error",
        "message": "bad",
        "object_uuid": None,
        "field_path": ["a"],
        "path": None,
        "line": None,
        "column": None,
        "end_column": None,
        "help": None,
        "fix": None,
        "explain": "opentide explain yaml_parse",
    }


def test_lint_and_validate_render_a_yaml_error_alike(workspace: Path) -> None:
    sources = SourceFiles()
    finding = {
        "check": "filenames",
        "severity": "error",
        "path": "objects/rules/broken.yaml",
        "yaml_line": None,
        "uuid": None,
        "message": "Could not parse object YAML: did not find … at line 8, column 9 (…)",
        "code": "yaml_parse",
        "line": 8,
        "column": 9,
    }
    linted = diagnostic_from_lint_finding(finding, root=workspace, sources=sources)
    validated = diagnostic_from_issue(_syntax(workspace), workspace=workspace, sources=sources)
    shown = ("message", "line", "column", "end_column", "notes", "path")
    assert {key: getattr(linted, key) for key in shown} == {
        key: getattr(validated, key) for key in shown
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
    merged = merge_reference_findings([vocab, other, _dangling(workspace)])
    assert [issue.code for issue in merged] == ["vocab_unknown", "invalid_ref"]
    assert merged[0] is other
    assert merged[1].suggestion == "00000000-0000-4000-8002-000000000001"


def test_a_value_repeated_in_a_list_is_reported_where_each_one_is(tmp_path: Path) -> None:
    """Each occurrence keeps its invalid_ref, and each points at its own line."""
    objective = tmp_path / "objective.yaml"
    objective.write_text(
        f"objective:\n  threats:\n    - {DANGLING}\n    - other\n    - {DANGLING}\n",
        encoding="utf-8",
    )
    ref = ValidationIssue(
        code="invalid_ref",
        object_uuid=UUID,
        file_path=objective,
        field_path=("objective", "threats"),
        message=f"Unknown threat reference {DANGLING!r}",
        context={"value": DANGLING},
    )
    vocab = ref.model_copy(
        update={"code": "vocab_unknown", "field_path": ("objective", "threats", "0")}
    )
    merged = merge_reference_findings([vocab, ref, ref])
    assert [issue.code for issue in merged] == ["invalid_ref", "invalid_ref"]
    diagnostics = diagnostics_from_issues(merged, workspace=tmp_path)
    assert [(item.line, item.column) for item in diagnostics] == [(3, 7), (5, 7)]


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


def test_an_unencodable_source_line_never_raises(tmp_path: Path) -> None:
    """A cp1252 pipe (Windows CI, pre-commit) cannot write an emoji from the file."""
    path = tmp_path / "rule.yaml"
    path.write_text("metadata:\n  tlp: clearr  # \U0001f525 hot\n", encoding="utf-8")
    issue = ValidationIssue(
        code="vocab_unknown",
        file_path=path,
        yaml_line=1,
        field_path=("metadata", "tlp"),
        message="Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry \u2192 \U0001f525",
        suggestion="clear",
        context={"vocab": "tlp::1.0", "value": "clearr"},
    )
    sources = SourceFiles()
    diagnostic = diagnostic_from_issue(issue, workspace=tmp_path, sources=sources)
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n")
    console = Console(file=stream, width=72, color_system=None)
    render_diagnostics(console, [diagnostic], sources=sources, mode=OutputMode.PLAIN, cwd=tmp_path)
    stream.flush()
    text = raw.getvalue().decode("cp1252")
    assert "2 |   tlp: clearr  # ? hot" in text
    assert "  |        ^^^^^^ not in tlp::1.0" in text
    assert "error[vocab_unknown]: 'clearr' is not a TLP value" in text


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("techniques: [T1059,\tT1O59]", "\t"),
        ("techniques: ['日本語テキスト', T1O59]", "  " * 7),
    ],
    ids=["tab", "wide"],
)
def test_the_underline_follows_terminal_cells(tmp_path: Path, line: str, expected: str) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(line + "\n", encoding="utf-8")
    issue = ValidationIssue(
        code="vocab_unknown",
        file_path=path,
        field_path=("techniques",),
        message="m",
        context={"value": "T1O59"},
    )
    sources = SourceFiles()
    diagnostic = diagnostic_from_issue(issue, workspace=tmp_path, sources=sources)
    console = _console(human=False)
    render_diagnostics(console, [diagnostic], sources=sources, mode=OutputMode.PLAIN, cwd=tmp_path)
    rows = console.export_text().splitlines()
    source = next(row for row in rows if row.startswith("1 │"))
    underline = next(row for row in rows if "━" in row)
    assert cell_len(source[: source.index("T1O59")]) == cell_len(underline[: underline.index("━")])
    assert underline.count("━") == 5
    assert expected in underline_offset(line, line.index("T1O59") + 1)


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
        ({"OPENTIDE_LINKS": "vscode"}, "vscode://file/w/rule.yaml:8:3"),
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


@pytest.mark.skipif(__import__("os").name == "nt", reason="POSIX paths")
def test_link_url_percent_encodes_the_path() -> None:
    path = Path("/w/Jane Doe/Simulated Actor#1.yaml")
    assert link_url(path, 2, 1, {}) == "file:///w/Jane%20Doe/Simulated%20Actor%231.yaml"
    assert link_url(path, 2, 1, {"OPENTIDE_LINKS": "cursor"}) == (
        "cursor://file/w/Jane%20Doe/Simulated%20Actor%231.yaml:2:1"
    )


def test_a_path_with_a_space_is_still_a_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENTIDE_LINKS", "vscode")
    folder = tmp_path / "Jane Doe"
    folder.mkdir()
    path = folder / "Simulated Actor.yaml"
    path.write_text("metadata:\n  tlp: clearr\n", encoding="utf-8")
    issue = ValidationIssue(
        code="vocab_unknown",
        file_path=path,
        field_path=("metadata", "tlp"),
        message="m",
        context={"value": "clearr"},
    )
    sources = SourceFiles()
    diagnostic = diagnostic_from_issue(issue, workspace=tmp_path, sources=sources)
    console = Console(file=io.StringIO(), force_terminal=True, width=72)
    render_diagnostics(console, [diagnostic], sources=sources, mode=OutputMode.HUMAN, cwd=tmp_path)
    assert "Jane%20Doe/Simulated%20Actor.yaml:2:8" in console.file.getvalue()  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# Spec wording, root-level positions and narrow terminals
# --------------------------------------------------------------------------


def test_a_vocabulary_typo_reads_as_the_spec_says(workspace: Path) -> None:
    """Diagnostics: ``'clearr' is not a TLP value``, not the engine's sentence."""
    diagnostic = diagnostic_from_issue(_typo(workspace), workspace=workspace, sources=SourceFiles())
    assert diagnostic.message == "'clearr' is not a TLP value"


def test_a_missing_top_level_field_points_at_the_top_mapping(workspace: Path) -> None:
    """E2E 9: the frame had no line, and the message was Pydantic's."""
    issue = ValidationIssue(
        code="schema_validation",
        file_path=_rule(workspace),
        field_path=("severity",),
        message="Field required",
    )
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.message == "missing required field 'severity'"
    assert diagnostic.label == "add 'severity' at the top level"
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (1, 1, 5)


def test_a_configuration_enum_case_typo_is_a_safe_fix(workspace: Path) -> None:
    """E2E 15: ``status: design`` for ``DESIGN`` is the same word, so it is a safe fix."""
    path = _rule(workspace)
    path.write_text(RULE + "    status: design\n", encoding="utf-8")
    issue = ValidationIssue(
        code="config_enum_unknown",
        file_path=path,
        field_path=("configurations", "sentinel", "status"),
        message="Value 'design' is not a configured statuses value.",
        suggestion="DESIGN",
        context={"setting": "statuses", "value": "design", "allowed": ["DESIGN", "STAGING"]},
    )
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=SourceFiles())
    assert diagnostic.message == "'design' is not a configured status"
    assert diagnostic.label == "not in [[statuses]]"
    assert diagnostic.help == "did you mean 'DESIGN'?"
    assert diagnostic.fix == Fix(True, (TextEdit(15, 13, 19, "DESIGN"),))


def test_a_list_at_the_top_of_an_object_file_is_framed(tmp_path: Path) -> None:
    """E2E 3: 'expected a mapping', at the line where the document starts."""
    path = tmp_path / "listy.yaml"
    path.write_text("# a comment\n---\n- name: one\n- name: two\n", encoding="utf-8")
    issue = ValidationIssue(
        code="yaml_parse",
        file_path=path,
        message="Could not parse object YAML: expected a mapping at the top of the file",
    )
    diagnostic = diagnostic_from_issue(issue, workspace=tmp_path, sources=SourceFiles())
    assert diagnostic.message == "expected a mapping at the top of the file, found a list"
    assert (diagnostic.line, diagnostic.column, diagnostic.end_column) == (3, 1, 12)
    assert diagnostic.notes[0][0] == "help"


def test_wrap_text_breaks_at_spaces_then_at_path_segments() -> None:
    from rich.text import Text

    from opentide.cli.ui.codeframe import wrap_text

    lines = wrap_text(Text("error: one two three four"), 12, Text("  "))
    assert [line.plain for line in lines] == ["error: one", "  two three", "  four"]
    lines = wrap_text(Text("at objects/rules/long-name.yaml"), 16, Text(""))
    assert [line.plain for line in lines] == ["at", "objects/rules/", "long-name.yaml"]


def test_shorten_path_keeps_the_ends() -> None:
    from opentide.cli.ui.codeframe import shorten_path

    location = "objects/rules/team/sentinel-kql-rule.yaml:8:8"
    assert shorten_path(location, 80) == location
    assert shorten_path(location, 40) == "objects/…/sentinel-kql-rule.yaml:8:8"
    shortened = shorten_path(location, 20)
    assert len(shortened) == 20 and shortened.startswith("obj") and shortened.endswith(":8:8")


@pytest.mark.parametrize("mode", [OutputMode.HUMAN, OutputMode.PLAIN])
def test_a_narrow_terminal_never_breaks_a_word(
    workspace: Path, mode: OutputMode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E2E 7: at 60 columns the terminal broke messages and paths mid-word."""
    monkeypatch.setenv("OPENTIDE_LINKS", "none")
    long_name = "sentinel-kql-rule-with-a-much-longer-file-name-here.yaml"
    _rule(workspace).rename(_rule(workspace, long_name))
    issue = ValidationIssue(
        code="invalid_value",
        file_path=_rule(workspace, long_name),
        field_path=("metadata", "tlp"),
        message="the value 'clearr' is not one of the values this vocabulary allows today",
        suggestion="choose one of the values the tlp vocabulary lists, such as clear or green",
    )
    sources = SourceFiles()
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=sources)
    console = Console(file=io.StringIO(), force_terminal=True, width=60, record=True)
    render_diagnostics(console, [diagnostic], sources=sources, mode=mode, cwd=workspace)
    lines = console.export_text().splitlines()
    assert all(cell_len(line) <= 60 for line in lines), lines
    assert "…" in lines[2] and lines[2].endswith(":7:8"), lines
    # Every word of the message and the help survives whole.
    words = set(" ".join(lines).split())
    assert set(issue.message.split()) <= words
    assert set(str(issue.suggestion).split()) <= words


def test_a_pipe_keeps_lines_whole(workspace: Path) -> None:
    """Without a terminal nothing is wrapped: the reader (a CI log, an editor) wraps it."""
    long_name = "sentinel-kql-rule-with-a-much-longer-file-name-here.yaml"
    _rule(workspace).rename(_rule(workspace, long_name))
    issue = _typo(workspace).model_copy(update={"file_path": _rule(workspace, long_name)})
    sources = SourceFiles()
    diagnostic = diagnostic_from_issue(issue, workspace=workspace, sources=sources)
    console = Console(file=io.StringIO(), width=60, record=True)
    render_diagnostics(console, [diagnostic], sources=sources, mode=OutputMode.PLAIN, cwd=workspace)
    assert f"objects/rules/{long_name}:7:8" in console.export_text()
