"""Platform import extraction services.

Importers talk to a vendor API, so they need that vendor's SDK. The CLI has to
tell the two failure modes apart: a genuinely missing extraction module is a
packaging bug, while a missing SDK is one `pip install` away. Collapsing both
into "Extraction module not found" sent users looking for a file that was
there all along (#242).
"""

from __future__ import annotations

import importlib
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

#: Extra that provides the vendor SDK each importer needs, keyed by target.
_IMPORT_EXTRAS: dict[ExtractImport, str] = {
    ExtractImport.sentinel: "opentide[sentinel]",
}


class ExtractionDependencyError(RuntimeError):
    """An importer is installed but the SDK it imports is not."""


def _root_package(exc: ModuleNotFoundError) -> str:
    return (exc.name or "").split(".", 1)[0]


def _run_engine_module(module_name: str, target: ExtractImport) -> None:
    """Import the packaged extraction module and run it."""
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if _root_package(exc) == module_name.split(".", 1)[0]:
            raise FileNotFoundError(f"Extraction module not found: {module_name}") from exc
        extra = _IMPORT_EXTRAS.get(target)
        advice = f"install {extra}" if extra else f"install the {_root_package(exc)} package"
        raise ExtractionDependencyError(
            f"{target.value} import needs a vendor SDK that is not installed ({exc.name}); {advice}"
        ) from exc
    runner = getattr(module, "run", None)
    if runner is None:
        raise FileNotFoundError(f"Extraction module has no run(): {module_name}")
    runner()


def run_extract_import(target: ExtractImport) -> None:
    """Run a platform import module from the installed package."""
    _run_engine_module(_IMPORT_MODULES[target], target)


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
