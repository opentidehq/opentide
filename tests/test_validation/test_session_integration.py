"""Integration-style session tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.session import run_validation


def test_run_validation_schema_check_on_rule() -> None:
    index = {
        "objects": {
            "rule": {
                "00000000-0000-4000-8000-000000000001": {
                    "name": "Incomplete",
                }
            },
            "objective": {},
            "threat": {},
        },
        "metaschemas": {"rule": {}},
        "files": {"00000000-0000-4000-8000-000000000001": "rule.yaml"},
        "vocabs": {},
        "configurations": {
            "global": {"objects": ["rule", "objective", "threat"], "metaschemas": {}},
            "documentation": {},
            "schema": {},
        },
    }
    graph = MagicMock()
    graph.resolve.return_value = MagicMock(file_path=None)
    graph.enum_values.return_value = frozenset()
    with (
        patch("opentide.validation.session.OpenTide.initialise"),
        patch("opentide.validation.session.PreflightGraph.build", return_value=graph),
        patch(
            "opentide.validation.session.validate_object_vocab_from_metaschema",
            return_value=[],
        ),
        patch(
            "opentide.validation.session.check_references_for_object",
            return_value=[],
        ),
    ):
        report = run_validation(
            checks=frozenset({ValidateCheck.schema}),
            index=index,
            workers=0,
        )
    assert not report.ok
    assert report.stats["objects_checked"] == 1
