"""``validate --fix``: which edits apply, and that nothing else in the file changes."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from opentide.cli.ui.diagnostics import Diagnostic, Fix, TextEdit
from opentide.cli.ui.fixes import FixChange, FixPlan, end_line, plan_fixes, safe_edits

_THREAT = (
    "# Simulated threat, kept for the tutorial\n"
    "name: Simulated Actor\n"
    "criticality: Hihg   # typo, but not a safe fix\n"
    "metadata:\n"
    "  tlp: clearr\n"
    "threat:\n"
    "  impact:\n"
    '    - "Data Breech"\n'
    "    - 'Data Loss'\n"
)


def _write(tmp_path: Path, text: str, name: str = "threat.yaml") -> Path:
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return path


def _diagnostic(
    path: Path,
    line: int,
    column: int,
    end_column: int,
    replacement: str,
    *,
    safe: bool = True,
    code: str = "vocab_unknown",
) -> Diagnostic:
    edit = TextEdit(line, column, end_column, replacement)
    return Diagnostic(
        code=code,
        severity="error",
        message="unknown value",
        path=path.name,
        file_path=path,
        line=line,
        column=column,
        end_column=end_column,
        fix=Fix(safe, (edit,)),
    )


def test_only_safe_edits_apply_and_every_other_byte_is_kept(tmp_path: Path) -> None:
    path = _write(tmp_path, _THREAT)
    plan = plan_fixes(
        [
            _diagnostic(path, 3, 14, 18, "High", safe=False),
            _diagnostic(path, 5, 8, 14, "clear"),
            _diagnostic(path, 8, 8, 19, "Data Breach"),
        ]
    )
    assert [change.to_dict() for change in plan.changes] == [
        {
            "path": "threat.yaml",
            "line": 5,
            "code": "vocab_unknown",
            "before": "clearr",
            "after": "clear",
        },
        {
            "path": "threat.yaml",
            "line": 8,
            "code": "vocab_unknown",
            "before": "Data Breech",
            "after": "Data Breach",
        },
    ]
    assert plan.file_count == 1
    assert path.read_bytes().decode() == _THREAT, "planning writes nothing"
    plan.write()
    assert path.read_bytes().decode() == (
        _THREAT.replace("tlp: clearr", "tlp: clear").replace('"Data Breech"', '"Data Breach"')
    )


def test_line_endings_and_a_missing_final_newline_survive(tmp_path: Path) -> None:
    text = "name: x\r\nmetadata:\r\n  tlp: clearr\r\nnote: last"
    path = _write(tmp_path, text)
    plan = plan_fixes([_diagnostic(path, 3, 8, 14, "clear")])
    plan.write()
    assert path.read_bytes() == text.replace("clearr", "clear").encode()


def test_the_dry_run_diff_is_unified_and_names_the_file(tmp_path: Path) -> None:
    path = _write(tmp_path, _THREAT)
    plan = plan_fixes([_diagnostic(path, 5, 8, 14, "clear")])
    assert plan.diff() == (
        "--- a/threat.yaml\n"
        "+++ b/threat.yaml\n"
        "@@ -2,7 +2,7 @@\n"
        " name: Simulated Actor\n"
        " criticality: Hihg   # typo, but not a safe fix\n"
        " metadata:\n"
        "-  tlp: clearr\n"
        "+  tlp: clear\n"
        " threat:\n"
        "   impact:\n"
        '     - "Data Breech"\n'
    )


def test_a_diff_marks_a_file_without_a_final_newline(tmp_path: Path) -> None:
    path = _write(tmp_path, "tlp: clearr")
    diff = plan_fixes([_diagnostic(path, 1, 6, 12, "clear")]).diff()
    assert diff.endswith(
        "-tlp: clearr\n\\ No newline at end of file\n+tlp: clear\n\\ No newline at end of file\n"
    )


@pytest.mark.parametrize(
    ("replacement", "why"),
    [
        ("a: b", "turns the value into a mapping"),
        ("&anchor", "turns the value into an anchor"),
        ("clear # x", "comments the rest out"),
        ("", "empties the value"),
    ],
)
def test_an_edit_that_changes_more_than_the_value_is_left_out(
    tmp_path: Path, replacement: str, why: str
) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: clearr\nname: x\n")
    plan = plan_fixes([_diagnostic(path, 2, 8, 14, replacement)])
    assert not plan, why
    assert plan.diff() == ""


def test_an_edit_whose_span_no_longer_holds_the_value_is_left_out(tmp_path: Path) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: clearr\n")
    # The file changed after validation: the columns now point past the line.
    assert not plan_fixes([_diagnostic(path, 2, 8, 30, "clear")])
    assert not plan_fixes([_diagnostic(path, 9, 1, 2, "clear")])
    assert not plan_fixes([_diagnostic(path, 2, 8, 8, "clear")])


def test_an_unreadable_or_unparsable_file_is_left_alone(tmp_path: Path) -> None:
    broken = _write(tmp_path, "metadata: [clearr\n", "broken.yaml")
    missing = tmp_path / "missing.yaml"
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"\xff\xfe")
    plan = plan_fixes(
        [
            _diagnostic(broken, 1, 12, 18, "clear"),
            _diagnostic(missing, 1, 1, 2, "x"),
            _diagnostic(binary, 1, 1, 2, "x"),
        ]
    )
    assert not plan
    assert plan.files == {}


def test_the_same_edit_twice_applies_once_and_overlaps_are_skipped(tmp_path: Path) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: clearr\n")
    plan = plan_fixes(
        [
            _diagnostic(path, 2, 8, 14, "clear"),
            _diagnostic(path, 2, 8, 14, "clear", code="invalid_ref"),
            _diagnostic(path, 2, 9, 12, "lea"),
        ]
    )
    assert [(change.code, change.after) for change in plan.changes] == [("vocab_unknown", "clear")]


def test_two_edits_on_one_line_both_apply(tmp_path: Path) -> None:
    path = _write(tmp_path, "values: [clearr, ambre]\n")
    plan = plan_fixes(
        [_diagnostic(path, 1, 10, 16, "clear"), _diagnostic(path, 1, 18, 23, "amber")]
    )
    plan.write()
    assert path.read_text() == "values: [clear, amber]\n"
    assert [change.column for change in plan.changes] == [10, 18]


def test_a_second_run_finds_nothing_left_to_fix(tmp_path: Path) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: clearr\n")
    plan_fixes([_diagnostic(path, 2, 8, 14, "clear")]).write()
    # Validation no longer reports it, so a second --fix has nothing to apply.
    assert not plan_fixes([])
    assert path.read_text() == "metadata:\n  tlp: clear\n"


def test_safe_edits_ignores_unsafe_and_fileless_findings(tmp_path: Path) -> None:
    path = _write(tmp_path, "tlp: clearr\n")
    assert safe_edits(_diagnostic(path, 1, 6, 12, "clear", safe=False)) == ()
    assert safe_edits(Diagnostic(code="x", severity="error", message="m")) == ()
    fileless = Diagnostic(
        code="x",
        severity="error",
        message="m",
        fix=Fix(True, (TextEdit(1, 1, 2, "y"),)),
    )
    assert safe_edits(fileless) == ()


def test_an_empty_plan_is_falsy_and_writes_nothing(tmp_path: Path) -> None:
    plan = FixPlan()
    assert not plan
    assert plan.file_count == 0
    plan.write()
    change = FixChange(
        path="a.yaml",
        file_path=tmp_path / "a.yaml",
        line=1,
        column=1,
        code="vocab_unknown",
        before="x",
        after="y",
    )
    assert FixPlan(changes=(change,))


def test_a_file_that_cannot_be_written_is_reported_and_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    locked = _write(tmp_path, "tlp: clearr\n", "locked.yaml")
    open_ = _write(tmp_path, "tlp: clearr\n", "open.yaml")
    real_write = Path.write_bytes

    def write_bytes(self: Path, data: bytes) -> int:
        if self == locked:
            raise PermissionError(13, "Permission denied")
        return real_write(self, data)

    monkeypatch.setattr(Path, "write_bytes", write_bytes)
    plan = plan_fixes(
        [_diagnostic(locked, 1, 6, 12, "clear"), _diagnostic(open_, 1, 6, 12, "clear")]
    )
    written, failed = plan.write()
    assert failed == ["locked.yaml: Permission denied"]
    assert [change.path for change in written.changes] == ["open.yaml"]
    assert written.file_count == 1
    assert locked.read_text() == "tlp: clearr\n"
    assert open_.read_text() == "tlp: clear\n"


@dataclass(frozen=True)
class _SpanningEdit:
    """A ``TextEdit`` with ``end_line``, as diagnostics may carry."""

    line: int
    column: int
    end_line: int
    end_column: int
    replacement: str


def test_an_edit_may_span_lines_and_counts_code_points(tmp_path: Path) -> None:
    path = _write(tmp_path, "note: é\ndescription: Detects\n  credential acces\nname: x\n")
    edit = _SpanningEdit(
        line=2, column=14, end_line=3, end_column=19, replacement="Detects credential access"
    )
    diagnostic = replace(_diagnostic(path, 2, 14, 21, "unused"), fix=Fix(True, (edit,)))  # type: ignore[arg-type]
    written, failed = plan_fixes([diagnostic]).write()
    assert failed == []
    assert [change.before for change in written.changes] == ["Detects\n  credential acces"]
    assert path.read_text() == "note: é\ndescription: Detects credential access\nname: x\n"
    assert end_line(edit) == 3  # type: ignore[arg-type]
    assert end_line(TextEdit(4, 1, 2, "x")) == 4
    # "é" is one column, whatever its UTF-8 length.
    accented = _write(tmp_path, "tlp: [é, clearr]\n", "accented.yaml")
    plan = plan_fixes([_diagnostic(accented, 1, 10, 16, "clear")])
    assert [change.before for change in plan.changes] == ["clearr"]


def test_an_edit_that_changes_two_values_is_left_out(tmp_path: Path) -> None:
    path = _write(tmp_path, "values: [clearr,\n  ambre]\nother: {a: 1}\n")
    edit = _SpanningEdit(line=1, column=10, end_line=2, end_column=8, replacement="clear, amber")
    diagnostic = replace(_diagnostic(path, 1, 10, 16, "unused"), fix=Fix(True, (edit,)))  # type: ignore[arg-type]
    assert not plan_fixes([diagnostic])
    shape = _SpanningEdit(line=3, column=8, end_line=3, end_column=14, replacement="[1]")
    changed = replace(_diagnostic(path, 3, 8, 14, "unused"), fix=Fix(True, (shape,)))  # type: ignore[arg-type]
    assert not plan_fixes([changed]), "a mapping turned into a list"
