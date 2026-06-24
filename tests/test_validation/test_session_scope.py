"""Validation session scope and ID-uniqueness behaviour."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.id_scan import IdScanRow, id_duplicate_in_scope, merge_id_duplicates
from opentide.validation.scope import ValidationScope, has_narrow_filter, scope_no_match_issue
from opentide.validation.session import run_validation


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


def test_run_validation_empty_narrow_scope_fails() -> None:
    index = {
        "objects": {"rule": {}, "objective": {}, "threat": {}},
        "metaschemas": {},
        "files": {},
        "vocabs": {},
    }
    scope = ValidationScope.narrow(uuids=frozenset({"00000000-0000-4000-8000-000000000099"}))
    with (
        patch("opentide.validation.session.OpenTide.initialise"),
        patch("opentide.validation.session.PreflightGraph.build", return_value=MagicMock()),
    ):
        report = run_validation(
            scope=scope,
            checks=frozenset({ValidateCheck.schema}),
            index=index,
            workers=0,
        )
    assert not report.ok
    assert any(issue.code == "scope_no_match" for issue in report.issues)


def test_run_validation_uuid_scope_still_finds_duplicate_ids(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yaml").write_text(
        "name: A\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n",
        encoding="utf-8",
    )
    (rules_dir / "b.yaml").write_text(
        "name: B\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n",
        encoding="utf-8",
    )
    index = {
        "objects": {"rule": {}, "objective": {}, "threat": {}},
        "metaschemas": {"rule": {}},
        "files": {},
        "vocabs": {},
    }
    scope = ValidationScope.narrow(uuids=frozenset({"00000000-0000-4000-8000-000000000001"}))
    with (
        patch("opentide.validation.session.OpenTide.initialise"),
        patch("opentide.validation.session.PreflightGraph.build", return_value=MagicMock()),
        patch("opentide.validation.session.resolve_paths", return_value={"rule": rules_dir}),
        patch(
            "opentide.validation.session.resolve_configurations",
            return_value={"global": {"metaschemas": {"rule": {}}}},
        ),
    ):
        report = run_validation(
            scope=scope,
            checks=frozenset({ValidateCheck.id_uniqueness}),
            index=index,
            workers=0,
        )
    assert not report.ok
    assert any(issue.code == "duplicate_id" for issue in report.issues)
