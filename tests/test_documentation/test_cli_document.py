from __future__ import annotations

from unittest.mock import patch

from opentide.cli.enums import DocumentScope
from opentide.cli.services.document import run_document_all, run_document_scope


def test_run_document_all_delegates_to_cli() -> None:
    with patch("opentide.documentation.cli.run", return_value={"message": "ok"}) as run:
        result = run_document_all(output="docs", flavor="github")
    run.assert_called_once_with(scope=None, output="docs", flavor="github")
    assert result["message"] == "ok"


def test_run_document_scope_index() -> None:
    with patch("opentide.documentation.cli.run", return_value={"message": "index"}) as run:
        result = run_document_scope(DocumentScope.index, output="out")
    run.assert_called_once_with(scope="index", output="out", flavor=None)
    assert result["message"] == "index"
