"""Public ID scan and scope helper behaviour."""

from __future__ import annotations

from pathlib import Path

from opentide.validation.id_scan import IdScanRow, id_duplicate_in_scope, merge_id_duplicates
from opentide.validation.scope import ValidationScope, has_narrow_filter, scope_no_match_issue


def test_scope_has_narrow_filter() -> None:
    assert not has_narrow_filter(ValidationScope.full())
    assert has_narrow_filter(ValidationScope.narrow(uuids=frozenset({"x"})))


def test_scope_no_match_issue_fields() -> None:
    scope = ValidationScope.narrow(uuids=frozenset({"missing"}))
    issue = scope_no_match_issue(scope)
    assert issue.code == "scope_no_match"


def test_id_duplicate_in_scope_file_target() -> None:
    scope = ValidationScope.narrow(files=frozenset({"a.yaml"}))
    row = IdScanRow(Path("/repo/a.yaml"), "rule", "u1", "A")
    original = IdScanRow(Path("/repo/b.yaml"), "rule", "u1", "B")
    assert id_duplicate_in_scope(scope, row, original)


def test_id_duplicate_unrelated_files_skipped() -> None:
    scope = ValidationScope.narrow(files=frozenset({"other.yaml"}))
    row = IdScanRow(Path("a.yaml"), "rule", "u1", "A")
    original = IdScanRow(Path("b.yaml"), "rule", "u1", "B")
    assert not id_duplicate_in_scope(scope, row, original)


def test_merge_id_duplicates_respects_scope() -> None:
    scope = ValidationScope.narrow(files=frozenset({"new.yaml"}))
    scans = [
        IdScanRow(Path("existing.yaml"), "rule", "dup", "Existing"),
        IdScanRow(Path("new.yaml"), "rule", "dup", "New"),
    ]
    issues = merge_id_duplicates(scans, scope)
    assert len(issues) == 1
