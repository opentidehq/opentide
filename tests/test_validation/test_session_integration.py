"""Integration-style session tests with mocks."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.issues import ValidationReport
from opentide.validation.session import run_validation


def _run_schema_check(body: dict[str, Any]) -> ValidationReport:
    index = {
        "objects": {
            "rule": {"00000000-0000-4000-8000-000000000001": body},
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
    graph.enum_resolver.suggest.return_value = None
    with (
        patch("opentide.validation.session.Opentide.initialise"),
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
        return run_validation(
            checks=frozenset({ValidateCheck.schema}),
            index=index,
            workers=0,
        )


def test_run_validation_schema_check_on_rule() -> None:
    report = _run_schema_check({"name": "Incomplete", "metadata": {"schema": "rule::1.0"}})
    assert not report.ok
    assert report.stats["objects_checked"] == 1


def test_run_validation_reports_missing_schema_without_a_model() -> None:
    report = _run_schema_check({"name": "Incomplete", "metadata": {"tlp": "clear"}})
    assert [(i.code, i.field_path) for i in report.errors] == [
        ("schema_missing", ("metadata", "schema"))
    ]


def test_run_validation_reports_a_non_mapping_metadata_as_a_shape_error() -> None:
    report = _run_schema_check({"name": "Incomplete", "metadata": "rule::1.0"})
    assert [(i.code, i.field_path, i.message) for i in report.errors] == [
        ("schema_validation", ("metadata",), "Input should be a valid dictionary")
    ]


@pytest.mark.parametrize(
    ("schema", "message"),
    [
        ("rule::9.9", "unknown schema identifier: 'rule::9.9'"),
        ("threat::1.0", "'threat::1.0' is not a rule schema identifier"),
    ],
)
def test_run_validation_rejects_an_unknown_schema_without_a_model(
    schema: str, message: str
) -> None:
    report = _run_schema_check({"name": "Incomplete", "metadata": {"schema": schema}})
    assert [(i.code, i.field_path, i.message) for i in report.errors] == [
        ("schema_validation", ("metadata", "schema"), message)
    ]


def test_id_scan_skips_a_non_mapping_metadata(tmp_path: Path) -> None:
    """The id-uniqueness scan used to crash on `metadata: <scalar>` with AttributeError."""
    from opentide.validation.session import _scan_id_file

    rule = tmp_path / "rule.yaml"
    rule.write_text(
        "name: Scalar\nuuid: 00000000-0000-4000-8003-000000000001\nmetadata: rule::1.0\n"
    )
    assert _scan_id_file((rule, "rule")) is None


@pytest.mark.parametrize(
    ("relative", "block"),
    [
        ("Objects/Threat Vectors/threat-0001-simulated-actor.yaml", "threat"),
        ("Objects/Detection Objectives/objective-0001-credential-access.yaml", "objective"),
    ],
)
def test_run_validation_reports_an_empty_body_block(
    tide_corpus_repo: Path, relative: str, block: str
) -> None:
    """A block whose keys are all commented out used to crash the whole run.

    It loads as ``None`` and the reference checks called ``.get`` on it, so
    ``opentide --json validate`` printed a traceback instead of a report.
    """
    path = tide_corpus_repo / relative
    head, _sep, _tail = path.read_text(encoding="utf-8").partition(f"{block}:\n")
    path.write_text(f"{head}{block}:\n  # description: TODO\n", encoding="utf-8")

    report = run_validation(workers=0)

    assert [(i.code, i.field_path[:1]) for i in report.errors] == [("schema_validation", (block,))]
