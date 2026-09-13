"""CLI extraction service behaviour."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import ExtractImport
from opentide.cli.services import extraction as extraction_service


def test_run_extract_import_sentinel() -> None:
    with patch.object(extraction_service, "_run_engine_module") as mock_run:
        extraction_service.run_extract_import(ExtractImport.sentinel)
    mock_run.assert_called_once_with("opentide.extraction.sentinel_importer")


def test_run_extract_import_defender() -> None:
    with patch.object(extraction_service, "_run_engine_module") as mock_run:
        extraction_service.run_extract_import(ExtractImport.defender)
    mock_run.assert_called_once_with("opentide.extraction.mde_importer")


def test_run_extract_entrypoint() -> None:
    ctx = CliContext(json_output=True)
    with patch.object(extraction_service, "run_extract_import") as mock_import:
        result = extraction_service.run_extract(ctx, import_target=ExtractImport.sentinel)
    mock_import.assert_called_once_with(ExtractImport.sentinel)
    assert result["import"] == "sentinel"


def test_run_engine_module_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def _missing(name: str, run_name: str | None = None) -> dict[str, object]:
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(extraction_service.runpy, "run_module", _missing)
    with pytest.raises(FileNotFoundError, match="Extraction module not found"):
        extraction_service._run_engine_module("opentide.extraction.missing")
