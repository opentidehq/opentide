"""CLI document service behaviour."""

from __future__ import annotations

from unittest.mock import patch

from opentide.cli.context import CliContext
from opentide.cli.enums import DocumentScope
from opentide.cli.services import document as document_service


def test_run_document_full_pipeline() -> None:
    ctx = CliContext(json_output=True)
    with patch.object(document_service, "run_document_all", return_value={"rules": 1}) as mock_all:
        result = document_service.run_document(ctx)
    mock_all.assert_called_once()
    assert result["rules"] == 1


def test_run_document_scoped() -> None:
    ctx = CliContext(json_output=True)
    with patch.object(
        document_service, "run_document_scope", return_value={"rules": 2}
    ) as mock_scope:
        result = document_service.run_document(ctx, scope=DocumentScope.rules)
    mock_scope.assert_called_once_with(DocumentScope.rules, output=None, flavor=None)
    assert result["rules"] == 2


def test_run_document_scope_delegates() -> None:
    with patch("opentide.documentation.cli.run", return_value={"objectives": 1}) as mock_run:
        result = document_service.run_document_scope(DocumentScope.objectives, output="/tmp")
    mock_run.assert_called_once_with(scope="objectives", output="/tmp", flavor=None)
    assert result["objectives"] == 1


def test_run_document_all_delegates() -> None:
    with patch("opentide.documentation.cli.run", return_value={"index": 1}) as mock_run:
        result = document_service.run_document_all(flavor="github")
    mock_run.assert_called_once_with(scope=None, output=None, flavor="github")
    assert result["index"] == 1
