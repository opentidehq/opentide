"""Platform import extraction services.

Importers talk to a vendor API, so they need that vendor's SDK, which ships with
``pip install opentide``. The CLI still tells the two failure modes apart: a
missing extraction module is a packaging bug, while an SDK that will not import
means the environment is incomplete and a reinstall fixes it. Collapsing both
into "Extraction module not found" sent users looking for a file that was
there all along (#242).
"""

from __future__ import annotations

import importlib
from contextlib import redirect_stdout
from io import StringIO
from typing import TYPE_CHECKING, Any

from opentide.cli.enums import ExtractImport

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

_IMPORT_MODULES: dict[ExtractImport, str] = {
    ExtractImport.sentinel: "opentide.extraction.sentinel_importer",
    ExtractImport.defender: "opentide.extraction.mde_importer",
    ExtractImport.elastic: "opentide.extraction.elastic_importer",
}


class ExtractionDependencyError(RuntimeError):
    """An importer is installed but the SDK it imports will not import."""


def _root_package(exc: ModuleNotFoundError) -> str:
    return (exc.name or "").split(".", 1)[0]


def _dependency_error(target: ExtractImport, exc: ModuleNotFoundError) -> ExtractionDependencyError:
    from opentide.cli.services.validation import INCOMPLETE_INSTALL_ADVICE

    return ExtractionDependencyError(
        f"{target.value} import could not import {exc.name}: the opentide install is "
        f"incomplete; {INCOMPLETE_INSTALL_ADVICE}"
    )


def _run_engine_module(module_name: str, target: ExtractImport, **kwargs: object) -> Any:
    """Import the packaged extraction module and run it."""
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if _root_package(exc) == module_name.split(".", 1)[0]:
            raise FileNotFoundError(f"Extraction module not found: {module_name}") from exc
        raise _dependency_error(target, exc) from exc
    runner = getattr(module, "run", None)
    if runner is None:
        raise FileNotFoundError(f"Extraction module has no run(): {module_name}")
    try:
        return runner(**kwargs)
    except ModuleNotFoundError as exc:
        # Vendor SDKs are imported where the importer first talks to the tenant.
        raise _dependency_error(target, exc) from exc
    except TypeError as exc:
        raise TypeError(
            f"Extraction module runner in {module_name} failed with arguments "
            f"{list(kwargs.keys())}: {exc}"
        ) from exc


def run_extract_import(target: ExtractImport, **kwargs: object) -> Any:
    """Run a platform import module from the installed package."""
    return _run_engine_module(_IMPORT_MODULES[target], target, **kwargs)


def run_extract(
    ctx: CliContext,
    *,
    import_target: ExtractImport,
    **kwargs: object,
) -> dict[str, object]:
    """Entry point for extract import command."""
    from opentide.cli.services.generation import WrittenFiles
    from opentide.cli.ui.progress import Checklist, plural
    from opentide.core.root import get_repo_root

    ctx.apply_environment()
    captured = StringIO()
    run_res = None
    watch = WrittenFiles(get_repo_root())
    with (
        Checklist(total=1) as checklist,
        checklist.step(f"import from {import_target.value}", unit="rule") as step,
    ):
        if ctx.json_output:
            with redirect_stdout(captured):
                run_res = run_extract_import(import_target, **kwargs)
        else:
            run_res = run_extract_import(import_target, **kwargs)
        written = [path for path in watch.changes()[0] if path.suffix in (".yaml", ".yml")]
        step.done(len(written))
    result: dict[str, object] = {"import": import_target.value}
    if isinstance(run_res, dict):
        result.update(run_res)
    imported = result.get("extracted_count")
    count = imported if isinstance(imported, int) else len(written)
    skipped = result.get("skipped")
    skipped_count = len(skipped) if isinstance(skipped, list) else 0
    message = f"Imported {plural(count, 'rule')} from {import_target.value}"
    if skipped_count:
        message += f" · {skipped_count} skipped"
    result["message"] = message
    result["_summary"] = {"imported": count, "skipped": skipped_count}
    if captured.getvalue().strip():
        result["output"] = captured.getvalue().strip()
    return result
