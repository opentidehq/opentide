"""Validation session integration behaviour for scoped runs."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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
