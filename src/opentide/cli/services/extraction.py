"""Platform import extraction services."""

from __future__ import annotations

import runpy
from typing import TYPE_CHECKING

from opentide.cli.enums import ExtractImport
from opentide.core.root import get_repo_root

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

_IMPORT_SCRIPTS: dict[ExtractImport, str] = {
    ExtractImport.sentinel: "src/opentide/extraction/sentinel_importer.py",
    ExtractImport.defender: "src/opentide/extraction/mde_importer.py",
}


def _run_engine_script(relative_path: str) -> None:
    """Execute an extraction script via runpy (preserves script-style side effects)."""
    script = get_repo_root() / relative_path
    if not script.is_file():
        raise FileNotFoundError(f"Extraction script not found: {script}")
    runpy.run_path(str(script), run_name="__main__")


def run_extract_import(target: ExtractImport) -> None:
    """Run a platform import script."""
    _run_engine_script(_IMPORT_SCRIPTS[target])


def run_extract(
    ctx: CliContext,
    *,
    import_target: ExtractImport,
) -> dict[str, object]:
    """Entry point for extract import command."""
    ctx.apply_environment()
    run_extract_import(import_target)
    return {"message": f"Imported {import_target.value}", "import": import_target.value}
