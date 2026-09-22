"""CLI extraction service behaviour."""

from __future__ import annotations

import sys
import types
from unittest.mock import patch

import pytest

from opentide.cli.context import CliContext
from opentide.cli.enums import ExtractImport
from opentide.cli.services import extraction as extraction_service


def test_run_extract_import_sentinel() -> None:
    with patch.object(extraction_service, "_run_engine_module") as mock_run:
        extraction_service.run_extract_import(ExtractImport.sentinel)
    mock_run.assert_called_once_with(
        "opentide.extraction.sentinel_importer", ExtractImport.sentinel
    )


def test_run_extract_import_defender() -> None:
    with patch.object(extraction_service, "_run_engine_module") as mock_run:
        extraction_service.run_extract_import(ExtractImport.defender)
    mock_run.assert_called_once_with("opentide.extraction.mde_importer", ExtractImport.defender)


def test_run_extract_entrypoint() -> None:
    ctx = CliContext(json_output=True)
    with patch.object(extraction_service, "run_extract_import") as mock_import:
        result = extraction_service.run_extract(ctx, import_target=ExtractImport.sentinel)
    mock_import.assert_called_once_with(ExtractImport.sentinel)
    assert result["import"] == "sentinel"


def test_run_engine_module_missing() -> None:
    """A module the package should ship but does not is a packaging bug."""
    with pytest.raises(FileNotFoundError, match="Extraction module not found"):
        extraction_service._run_engine_module("opentide.extraction.missing", ExtractImport.sentinel)


def test_run_engine_module_names_the_missing_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing vendor SDK names the extra rather than the importer (#242)."""

    def _no_sdk(name: str) -> types.ModuleType:
        raise ModuleNotFoundError("No module named 'azure'", name="azure")

    monkeypatch.setattr(extraction_service.importlib, "import_module", _no_sdk)
    with pytest.raises(extraction_service.ExtractionDependencyError) as excinfo:
        extraction_service._run_engine_module(
            "opentide.extraction.sentinel_importer", ExtractImport.sentinel
        )
    assert "opentide[sentinel]" in str(excinfo.value)
    assert "Extraction module not found" not in str(excinfo.value)


def test_run_engine_module_requires_a_run_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("opentide.extraction.no_run")
    monkeypatch.setitem(sys.modules, "opentide.extraction.no_run", module)
    with pytest.raises(FileNotFoundError, match="has no run\\(\\)"):
        extraction_service._run_engine_module("opentide.extraction.no_run", ExtractImport.defender)
