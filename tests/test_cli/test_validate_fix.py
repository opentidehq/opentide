"""``validate --fix``: which edits apply, and that nothing else in the file changes.

The fixes here are safe the way the diagnostics make them safe
(:func:`~opentide.cli.ui.diagnostics.is_safe_replacement`): the value written
and the replacement spell the same word, in another case or with ``-`` for a
space. ``--fix`` checks that again against the text it finds.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from opentide.cli.ui import fixes
from opentide.cli.ui.diagnostics import Diagnostic, Fix, TextEdit
from opentide.cli.ui.fixes import FixChange, FixPlan, line_starts, plan_fixes, safe_edits

_THREAT = (
    "# Simulated threat, kept for the tutorial\n"
    "name: Simulated Actor\n"
    "criticality: Hihg   # a typo, but not a safe fix\n"
    "metadata:\n"
    "  tlp: Clear\n"
    "threat:\n"
    "  impact:\n"
    '    - "Data-Breach"\n'
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


def _spanning(path: Path, edit: TextEdit) -> Diagnostic:
    return replace(
        _diagnostic(path, edit.line, edit.column, edit.end_column, edit.replacement),
        fix=Fix(True, (edit,)),
    )


def test_only_safe_edits_apply_and_every_other_byte_is_kept(tmp_path: Path) -> None:
    path = _write(tmp_path, _THREAT)
    plan = plan_fixes(
        [
            _diagnostic(path, 3, 14, 18, "High", safe=False),
            _diagnostic(path, 5, 8, 13, "clear"),
            _diagnostic(path, 8, 8, 19, "Data Breach"),
        ]
    )
    assert [change.to_dict() for change in plan.changes] == [
        {
            "path": "threat.yaml",
            "line": 5,
            "code": "vocab_unknown",
            "before": "Clear",
            "after": "clear",
        },
        {
            "path": "threat.yaml",
            "line": 8,
            "code": "vocab_unknown",
            "before": "Data-Breach",
            "after": "Data Breach",
        },
    ]
    assert plan.file_count == 1
    assert path.read_bytes().decode() == _THREAT, "planning writes nothing"
    written, failed = plan.write()
    assert (written.changes, failed) == (plan.changes, [])
    assert path.read_bytes().decode() == (
        _THREAT.replace("tlp: Clear", "tlp: clear").replace('"Data-Breach"', '"Data Breach"')
    )


def test_line_endings_and_a_missing_final_newline_survive(tmp_path: Path) -> None:
    text = "name: x\r\nmetadata:\r\n  tlp: Clear\r\nnote: last"
    path = _write(tmp_path, text)
    plan_fixes([_diagnostic(path, 3, 8, 13, "clear")]).write()
    assert path.read_bytes() == text.replace("Clear", "clear").encode()


def test_an_old_mac_line_ending_file_is_edited_in_place(tmp_path: Path) -> None:
    text = "name: x\rmetadata:\r  tlp: CLEAR\r"
    path = _write(tmp_path, text)
    plan = plan_fixes([_diagnostic(path, 3, 8, 13, "clear")])
    assert "No newline" not in plan.diff()
    plan.write()
    assert path.read_bytes() == text.replace("CLEAR", "clear").encode()


def test_lines_are_numbered_as_yaml_numbers_them() -> None:
    text = "a: 1\r\nb: 2\rc: 3\nd: 4"
    assert [text[start:end] for start, end in line_starts(text)] == [
        "a: 1",
        "b: 2",
        "c: 3",
        "d: 4",
    ]


def test_the_dry_run_diff_is_unified_and_names_the_file(tmp_path: Path) -> None:
    path = _write(tmp_path, _THREAT)
    plan = plan_fixes([_diagnostic(path, 5, 8, 13, "clear")])
    assert plan.diff() == (
        "--- a/threat.yaml\n"
        "+++ b/threat.yaml\n"
        "@@ -2,7 +2,7 @@\n"
        " name: Simulated Actor\n"
        " criticality: Hihg   # a typo, but not a safe fix\n"
        " metadata:\n"
        "-  tlp: Clear\n"
        "+  tlp: clear\n"
        " threat:\n"
        "   impact:\n"
        '     - "Data-Breach"\n'
    )


def test_a_diff_marks_a_file_without_a_final_newline(tmp_path: Path) -> None:
    path = _write(tmp_path, "tlp: Clear")
    diff = plan_fixes([_diagnostic(path, 1, 6, 11, "clear")]).diff()
    assert diff.endswith(
        "-tlp: Clear\n\\ No newline at end of file\n+tlp: clear\n\\ No newline at end of file\n"
    )


@pytest.mark.skipif(shutil.which("patch") is None, reason="needs the patch tool")
def test_the_diff_applies_with_patch_beside_a_unicode_line_separator(tmp_path: Path) -> None:
    """U+2028 does not end a YAML line, so it must not split a diff line either."""
    text = 'name: x\nmetadata:\n  author: "Tutorial Author"\n  tlp: Clear\n  version: 1\n'  # noqa: RUF001
    path = _write(tmp_path, text, "rule.yaml")
    crlf = _write(tmp_path, "metadata:\r\n  tlp: Clear\r\n", "crlf.yaml")
    plan = plan_fixes([_diagnostic(path, 4, 8, 13, "clear"), _diagnostic(crlf, 2, 8, 13, "clear")])
    diff = plan.diff()
    assert '   author: "Tutorial Author"\n' in diff  # noqa: RUF001
    result = subprocess.run(
        ["patch", "--dry-run", "-p1", "-d", str(tmp_path)],
        input=diff.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()


@pytest.mark.parametrize(
    ("text", "replacement", "why"),
    [
        ("tlp: green\n", "clear", "a valid value saved over the typo since validation"),
        ("tlp: Clear\n", "a: b", "not a safe replacement for the text there"),
        ("tlp: Clear\n", "&clear", "not a safe replacement for the text there"),
    ],
)
def test_an_edit_is_kept_only_when_it_is_safe_for_the_text_found(
    tmp_path: Path, text: str, replacement: str, why: str
) -> None:
    path = _write(tmp_path, text)
    plan = plan_fixes([_diagnostic(path, 1, 6, 11, replacement)])
    assert not plan, why
    assert plan.diff() == ""
    assert path.read_text() == text


def test_a_value_saved_during_validation_is_not_overwritten(tmp_path: Path) -> None:
    """The finding was about ``Clear``; the author has since typed ``green``."""
    path = _write(tmp_path, "metadata:\n  tlp: Clear\n")
    finding = _diagnostic(path, 2, 8, 13, "clear")
    path.write_text("metadata:\n  tlp: green\n")
    assert not plan_fixes([finding])
    assert path.read_text() == "metadata:\n  tlp: green\n"


def test_a_safe_edit_that_breaks_the_document_is_left_out(tmp_path: Path) -> None:
    """Whitespace is ignorable to the safety rule; the parser decides it is not."""
    path = _write(tmp_path, "impact: Data-Breach\nname: x\n")
    assert not plan_fixes([_diagnostic(path, 1, 9, 20, "Data\nBreach")])


def test_only_change_requires_exactly_one_value_to_change() -> None:
    only_change = fixes._only_change
    assert only_change({"a": ["Clear", "x"]}, {"a": ["clear", "x"]}, "Clear", "clear")
    assert not only_change({"a": ["Clear", "Clear"]}, {"a": ["clear", "clear"]}, "Clear", "clear")
    assert not only_change({"a": {"b": 1}}, {"a": [1]}, "Clear", "clear"), "mapping to list"
    assert not only_change({"a": 1, "b": 2}, {"a": 1}, "Clear", "clear"), "a key went"
    assert not only_change(["Clear"], ["Clear", "x"], "Clear", "clear"), "an item came"


def test_an_edit_whose_span_no_longer_fits_is_left_out(tmp_path: Path) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: Clear\n")
    # The file changed after validation: the columns now point past the line.
    assert not plan_fixes([_diagnostic(path, 2, 8, 30, "clear")])
    assert not plan_fixes([_diagnostic(path, 9, 1, 2, "clear")])
    assert not plan_fixes([_diagnostic(path, 2, 8, 8, "clear")])


def test_an_unreadable_or_unparsable_file_is_left_alone(tmp_path: Path) -> None:
    broken = _write(tmp_path, "metadata: [Clear\n", "broken.yaml")
    missing = tmp_path / "missing.yaml"
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"\xff\xfe")
    plan = plan_fixes(
        [
            _diagnostic(broken, 1, 12, 17, "clear"),
            _diagnostic(missing, 1, 1, 2, "x"),
            _diagnostic(binary, 1, 1, 2, "x"),
        ]
    )
    assert not plan
    assert plan.files == {}


def test_the_same_edit_twice_applies_once_and_overlaps_are_skipped(tmp_path: Path) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: Clear\n")
    plan = plan_fixes(
        [
            _diagnostic(path, 2, 8, 13, "clear"),
            _diagnostic(path, 2, 8, 13, "clear", code="chaining_relation_unknown"),
            _diagnostic(path, 2, 9, 12, "lea"),
        ]
    )
    assert [(change.code, change.after) for change in plan.changes] == [("vocab_unknown", "clear")]


def test_two_edits_on_one_line_both_apply(tmp_path: Path) -> None:
    path = _write(tmp_path, "values: [Clear, AMBER]\n")
    plan = plan_fixes(
        [_diagnostic(path, 1, 10, 15, "clear"), _diagnostic(path, 1, 17, 22, "amber")]
    )
    plan.write()
    assert path.read_text() == "values: [clear, amber]\n"
    assert [change.column for change in plan.changes] == [10, 17]


def test_an_edit_may_span_lines_and_counts_code_points(tmp_path: Path) -> None:
    path = _write(tmp_path, "note: é\ndescription: Detects\n  Credential Access\nname: x\n")
    edit = TextEdit(
        line=2, column=14, end_line=3, end_column=20, replacement="Detects credential access"
    )
    written, failed = plan_fixes([_spanning(path, edit)]).write()
    assert failed == []
    assert [change.before for change in written.changes] == ["Detects\n  Credential Access"]
    assert path.read_text() == "note: é\ndescription: Detects credential access\nname: x\n"
    # "é" is one column, whatever its UTF-8 length.
    accented = _write(tmp_path, "tlp: [é, Clear]\n", "accented.yaml")
    plan = plan_fixes([_diagnostic(accented, 1, 10, 15, "clear")])
    assert [change.before for change in plan.changes] == ["Clear"]


def test_a_second_run_finds_nothing_left_to_fix(tmp_path: Path) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: Clear\n")
    plan_fixes([_diagnostic(path, 2, 8, 13, "clear")]).write()
    # Validation no longer reports it, so a second --fix has nothing to apply.
    assert not plan_fixes([])
    assert path.read_text() == "metadata:\n  tlp: clear\n"


def test_safe_edits_ignores_unsafe_and_fileless_findings(tmp_path: Path) -> None:
    path = _write(tmp_path, "tlp: Clear\n")
    assert safe_edits(_diagnostic(path, 1, 6, 11, "clear", safe=False)) == ()
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
    assert plan.write() == (FixPlan(), [])
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


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------


def _leftovers(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir() if path.name.endswith(".tmp"))


def test_a_write_that_fails_partway_leaves_the_original_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "# padding\n" * 50 + "metadata:\n  tlp: Clear\n"
    path = _write(tmp_path, text)
    plan = plan_fixes([_diagnostic(path, 52, 8, 13, "clear")])
    real_fdopen = os.fdopen

    class FullDisk:
        """Writes half of what it is given, then runs out of space."""

        def __init__(self, stream) -> None:
            self.stream = stream

        def __enter__(self) -> FullDisk:
            return self

        def __exit__(self, *exc: object) -> None:
            self.stream.close()

        def write(self, data: bytes) -> int:
            self.stream.write(data[: len(data) // 2])
            raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(
        fixes.os, "fdopen", lambda handle, mode: FullDisk(real_fdopen(handle, mode))
    )
    written, failed = plan.write()
    assert failed == ["threat.yaml: No space left on device"]
    assert not written
    assert path.read_text() == text
    assert _leftovers(tmp_path) == []


def test_a_file_that_cannot_be_replaced_is_reported_and_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    locked = _write(tmp_path, "tlp: Clear\n", "locked.yaml")
    unlocked = _write(tmp_path, "tlp: Clear\n", "open.yaml")
    real_replace = os.replace

    def refuse(source: str, target: os.PathLike[str]) -> None:
        if Path(target) == locked.resolve():
            raise PermissionError(errno.EACCES, "Permission denied")
        real_replace(source, target)

    monkeypatch.setattr(fixes.os, "replace", refuse)
    plan = plan_fixes(
        [_diagnostic(locked, 1, 6, 11, "clear"), _diagnostic(unlocked, 1, 6, 11, "clear")]
    )
    written, failed = plan.write()
    assert failed == ["locked.yaml: Permission denied"]
    assert [change.path for change in written.changes] == ["open.yaml"]
    assert written.file_count == 1
    assert locked.read_text() == "tlp: Clear\n"
    assert unlocked.read_text() == "tlp: clear\n"
    assert _leftovers(tmp_path) == []


def test_a_symlinked_object_keeps_its_link_and_mode(tmp_path: Path) -> None:
    store = tmp_path / "store"
    store.mkdir()
    target = _write(store, "metadata:\n  tlp: Clear\n", "rule.yaml")
    target.chmod(0o640)
    link = tmp_path / "rule.yaml"
    link.symlink_to(target)
    written, failed = plan_fixes([_diagnostic(link, 2, 8, 13, "clear")]).write()
    assert (len(written.changes), failed) == (1, [])
    assert link.is_symlink()
    assert link.resolve() == target.resolve()
    assert target.read_text() == "metadata:\n  tlp: clear\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert _leftovers(store) == []


def test_a_file_saved_between_planning_and_writing_is_left_alone(tmp_path: Path) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: Clear\n")
    plan = plan_fixes([_diagnostic(path, 2, 8, 13, "clear")])
    path.write_text("metadata:\n  tlp: Clear\n  author: someone\n")
    written, failed = plan.write()
    assert not written
    assert failed == [
        "threat.yaml: it changed since it was read; run opentide validate --fix again"
    ]
    assert path.read_text() == "metadata:\n  tlp: Clear\n  author: someone\n"


def test_a_file_removed_before_writing_is_reported(tmp_path: Path) -> None:
    path = _write(tmp_path, "metadata:\n  tlp: Clear\n")
    plan = plan_fixes([_diagnostic(path, 2, 8, 13, "clear")])
    path.unlink()
    written, failed = plan.write()
    assert not written
    assert failed == ["threat.yaml: No such file or directory"]
