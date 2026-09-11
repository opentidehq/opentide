"""Platform import extraction services."""

from __future__ import annotations

import runpy
from contextlib import redirect_stdout
from io import StringIO
from typing import TYPE_CHECKING

from opentide.cli.enums import ExtractImport

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

_IMPORT_MODULES: dict[ExtractImport, str] = {
    ExtractImport.sentinel: "opentide.extraction.sentinel_importer",
    ExtractImport.defender: "opentide.extraction.mde_importer",
}


def _run_engine_module(module_name: str) -> None:
    """Execute a packaged extraction module via runpy (preserves script-style side effects)."""
    try:
        runpy.run_module(module_name, run_name="__main__")
    except ModuleNotFoundError as exc:
        raise FileNotFoundError(f"Extraction module not found: {module_name}") from exc


def run_extract_import(target: ExtractImport) -> None:
    """Run a platform import module from the installed package."""
    _run_engine_module(_IMPORT_MODULES[target])


def run_extract(
    ctx: CliContext,
    *,
    import_target: ExtractImport,
) -> dict[str, object]:
    """Entry point for extract import command."""
    ctx.apply_environment()
    captured = StringIO()
    if ctx.json_output:
        with redirect_stdout(captured):
            run_extract_import(import_target)
    else:
        run_extract_import(import_target)
    result: dict[str, object] = {
        "message": f"Imported {import_target.value}",
        "import": import_target.value,
    }
    if captured.getvalue().strip():
        result["output"] = captured.getvalue().strip()
    return result
