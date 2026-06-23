"""Framework extraction and import services."""

from __future__ import annotations

import runpy
from typing import TYPE_CHECKING

from opentide.cli.enums import ExtractFramework, ExtractImport
from opentide.core.files import resolve_paths
from opentide.core.root import get_repo_root

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

_LEGACY_FRAMEWORK_SCRIPTS: dict[ExtractFramework, str] = {
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


def run_extract_framework(framework: ExtractFramework, *, fetch: bool = False) -> None:
    """Run an external framework extraction script."""
    if framework == ExtractFramework.attack:
        from pathlib import Path

        from opentide.vocabulary.fetch_stix import fetch_latest_attack_stix
        from opentide.vocabulary.generate_actors import generate_actors_vocabs
        from opentide.vocabulary.generate_attack import generate_attack_vocabs

        if fetch:
            stix_dir = Path(resolve_paths()["resources"]) / "attack" / "stix"
            fetch_latest_attack_stix(stix_dir)
        else:
            stix_dir = Path(resolve_paths()["resources"]) / "attack" / "stix"
            if not (stix_dir / "enterprise-attack.json").is_file():
                fetch_latest_attack_stix(stix_dir)
        generate_attack_vocabs(fetch=False)
        generate_actors_vocabs()
        return

    if framework in _LEGACY_FRAMEWORK_SCRIPTS:
        _run_engine_script(_LEGACY_FRAMEWORK_SCRIPTS[framework])
        return

    raise ValueError(f"No extraction handler for framework: {framework}")


def run_extract_import(target: ExtractImport) -> None:
    """Run a platform import script."""
    _run_engine_script(_IMPORT_SCRIPTS[target])


def run_extract(
    ctx: CliContext,
    *,
    framework: ExtractFramework | None = None,
    import_target: ExtractImport | None = None,
    fetch: bool = False,
) -> dict[str, object]:
    """Entry point for extract command."""
    ctx.apply_environment()
    if framework is not None:
        run_extract_framework(framework, fetch=fetch)
        return {"message": f"Extracted {framework.value}", "framework": framework.value}
    if import_target is not None:
        run_extract_import(import_target)
        return {"message": f"Imported {import_target.value}", "import": import_target.value}
    raise ValueError("Specify a framework or import target")
