"""Framework extraction and import services."""

from __future__ import annotations

import runpy
from typing import TYPE_CHECKING

from opentide.cli.enums import ExtractFramework, ExtractImport
from opentide.core.root import get_repo_root

if TYPE_CHECKING:
    from opentide.cli.context import CliContext
_FRAMEWORK_SCRIPTS: dict[ExtractFramework, str] = {
    ExtractFramework.attack: "src/opentide/extraction/attack.py",
    ExtractFramework.d3fend: "src/opentide/extraction/d3fend_artifacts.py",
    ExtractFramework.engage: "src/opentide/extraction/engage.py",
    ExtractFramework.nist: "src/opentide/extraction/nist.py",
    ExtractFramework.react: "src/opentide/extraction/atc_react.py",
}
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


def run_extract_framework(framework: ExtractFramework) -> None:
    """Run an external framework extraction script."""
    _run_engine_script(_FRAMEWORK_SCRIPTS[framework])


def run_extract_import(target: ExtractImport) -> None:
    """Run a platform import script."""
    _run_engine_script(_IMPORT_SCRIPTS[target])


def run_extract(
    ctx: CliContext,
    *,
    framework: ExtractFramework | None = None,
    import_target: ExtractImport | None = None,
) -> dict[str, object]:
    """Entry point for extract command."""
    ctx.apply_environment()
    if framework is not None:
        run_extract_framework(framework)
        return {"message": f"Extracted {framework.value}", "framework": framework.value}
    if import_target is not None:
        run_extract_import(import_target)
        return {"message": f"Imported {import_target.value}", "import": import_target.value}
    raise ValueError("Specify a framework or import target")
