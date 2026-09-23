"""Validation session integration behaviour for scoped runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml
from tests.validation_support import assert_issues_point_at_their_objects

from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.scope import ValidationScope
from opentide.validation.session import run_validation


@pytest.fixture
def validation_session_mocks() -> MagicMock:
    with (
        patch("opentide.validation.session.OpenTide.initialise"),
        patch(
            "opentide.validation.session.PreflightGraph.build",
            return_value=MagicMock(),
        ) as graph,
    ):
        yield graph


def test_run_validation_empty_narrow_scope_fails(validation_session_mocks: MagicMock) -> None:
    del validation_session_mocks
    index = {
        "objects": {"rule": {}, "objective": {}, "threat": {}},
        "metaschemas": {},
        "files": {},
        "vocabs": {},
    }
    scope = ValidationScope.narrow(uuids=frozenset({"00000000-0000-4000-8000-000000000099"}))
    report = run_validation(
        scope=scope,
        checks=frozenset({ValidateCheck.schema}),
        index=index,
        workers=0,
    )
    assert not report.ok
    assert any(issue.code == "scope_no_match" for issue in report.issues)
    assert_issues_point_at_their_objects(report)


def test_run_validation_uuid_scope_still_finds_duplicate_ids(
    tmp_path: Path,
    validation_session_mocks: MagicMock,
) -> None:
    del validation_session_mocks
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
    assert_issues_point_at_their_objects(report)


@pytest.mark.parametrize(
    "files",
    [None, frozenset({"team-a/emea/b.yaml"}), frozenset({"b.yaml"})],
    ids=["full", "nested-path", "basename"],
)
def test_run_validation_finds_duplicate_ids_in_nested_folders(
    tmp_path: Path,
    validation_session_mocks: MagicMock,
    files: frozenset[str] | None,
) -> None:
    """The ID scan walked only the top of each folder, unlike the indexer."""
    del validation_session_mocks
    rules_dir = tmp_path / "rules"
    nested = rules_dir / "team-a" / "emea"
    nested.mkdir(parents=True)
    uuid = "00000000-0000-4000-8000-000000000001"
    (rules_dir / "a.yaml").write_text(f"name: A\nmetadata:\n  uuid: {uuid}\n", encoding="utf-8")
    (nested / "b.yaml").write_text(f"name: B\nmetadata:\n  uuid: {uuid}\n", encoding="utf-8")
    index = {
        "objects": {"rule": {}, "objective": {}, "threat": {}},
        "metaschemas": {"rule": {}},
        "files": {},
        "vocabs": {},
    }
    scope = (
        ValidationScope.full()
        if files is None
        else ValidationScope.narrow(files=files, roots=(rules_dir,))
    )
    with (
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
    duplicates = [issue for issue in report.issues if issue.code == "duplicate_id"]
    assert [issue.file_path for issue in duplicates] == [nested / "b.yaml"]
    assert_issues_point_at_their_objects(report)


_TWIN_LAYOUT = {
    "objects/rules/twin.yaml": ("rule", "00000000-0000-4000-8003-0000000000b1"),
    "objects/rules/team-a/twin.yaml": ("rule", "00000000-0000-4000-8003-0000000000b2"),
    "objects/rules/team-a/emea/twin.yaml": ("rule", "00000000-0000-4000-8003-0000000000b3"),
    "objects/threats/twin.yaml": ("threat", "00000000-0000-4000-8001-0000000000b1"),
    "objects/threats/actors/twin.yaml": ("threat", "00000000-0000-4000-8001-0000000000b2"),
    "objects/objectives/twin.yaml": ("objective", "00000000-0000-4000-8002-0000000000b1"),
    "objects/objectives/access/emea/twin.yaml": (
        "objective",
        "00000000-0000-4000-8002-0000000000b3",
    ),
}


@pytest.fixture
def twin_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A real index over same-named object files at several depths.

    Each object is a bare ``name`` + ``metadata``, so schema validation reports
    issues for every object it checks: the UUIDs in the report are exactly the
    objects in scope.
    """
    from opentide.core.index_manager import IndexManager
    from opentide.registry.builder import build_registry

    for relative, (object_type, uuid) in _TWIN_LAYOUT.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(
                {
                    "name": f"Twin {uuid[-2:]}",
                    "metadata": {"uuid": uuid, "schema": f"{object_type}::1.0", "tlp": "clear"},
                }
            ),
            encoding="utf-8",
        )
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))
    IndexManager._cache = None  # noqa: SLF001
    try:
        return build_registry()
    finally:
        IndexManager._cache = None  # noqa: SLF001


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        *((relative, {uuid}) for relative, (_, uuid) in _TWIN_LAYOUT.items()),
        ("twin.yaml", {uuid for _, uuid in _TWIN_LAYOUT.values()}),
        ("objects/rules/team-b/twin.yaml", set()),
    ],
)
def test_run_validation_checks_exactly_the_targeted_twin_and_blames_its_own_file(
    twin_workspace: dict[str, Any], tmp_path: Path, target: str, expected: set[str]
) -> None:
    """Class guard for #297: same basename at depth 1-3, across object types."""
    real_paths = {uuid: (tmp_path / rel).resolve() for rel, (_, uuid) in _TWIN_LAYOUT.items()}
    scope = ValidationScope.narrow(files=frozenset({target}), roots=(tmp_path,))
    with patch("opentide.validation.session.OpenTide.initialise"):
        report = run_validation(
            scope=scope,
            checks=frozenset({ValidateCheck.schema}),
            index=twin_workspace,
            workers=0,
        )
    reported = {issue.object_uuid for issue in report.issues if issue.object_uuid}
    assert reported == expected
    assert report.stats["objects_checked"] == len(expected)
    for issue in report.issues:
        if issue.object_uuid:
            assert issue.file_path is not None
            assert issue.file_path.resolve() == real_paths[issue.object_uuid], issue
    assert_issues_point_at_their_objects(report)
