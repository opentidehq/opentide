"""Generation pipeline services for the CLI."""

from __future__ import annotations
from typing import TYPE_CHECKING
from opentide.cli.enums import GeneratePhase
from opentide.core.index_manager import IndexManager
from opentide.core.registry import OpenTide
import structlog
from opentide.core.logging.console import emit_section

logger = structlog.get_logger("opentide.cli.services.generation")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext
_PHASE_ORDER: tuple[GeneratePhase, ...] = (
    GeneratePhase.object_vocab,
    GeneratePhase.templates,
    GeneratePhase.schemas,
    GeneratePhase.revisions,
    GeneratePhase.snippets,
    GeneratePhase.exports,
    GeneratePhase.playbook_map,
)


def run_generate_phase(phase: GeneratePhase, *, staging: bool = False) -> None:
    """Run a single generation phase."""
    if staging:
        import os

        os.environ["INDEX_OUTPUT"] = "cache"
    if phase is GeneratePhase.object_vocab:
        from opentide.indexing.object_vocab import run as generate_object_vocab

        emit_section("Object vocabulary generation")
        generate_object_vocab()
        return
    if phase is GeneratePhase.templates:
        from opentide.generation.template import run as generate_templates

        emit_section("Template generation")
        generate_templates()
        IndexManager.reload()
        OpenTide.reload()
        return
    if phase is GeneratePhase.schemas:
        from opentide.generation.schema import run as generate_schemas

        emit_section("JSON schema generation")
        generate_schemas()
        return
    if phase is GeneratePhase.revisions:
        from opentide.indexing.revisions import RevisionIndexer

        emit_section("Revision index generation")
        RevisionIndexer().run()
        return
    if phase is GeneratePhase.snippets:
        from opentide.generation import vscode_snippets

        emit_section("VS Code snippet generation")
        vscode_snippets.run()
        return
    if phase is GeneratePhase.exports:
        from opentide.export import attack_navigator_layer
        from opentide.export.table_export import TableExporter

        emit_section("Export generation")
        attack_navigator_layer.run()
        TableExporter().run()
        return
    if phase is GeneratePhase.playbook_map:
        from opentide.export.playbook_map import run as generate_playbook_map

        emit_section("Playbook map export")
        generate_playbook_map()
        return
    raise ValueError(f"Unknown generation phase: {phase}")


def run_generate_all(*, staging: bool = False) -> None:
    """Run the full generation pipeline (Orchestration/generate.py parity)."""
    for phase in _PHASE_ORDER:
        run_generate_phase(phase, staging=staging)


def run_generate(
    ctx: CliContext, *, phase: GeneratePhase | None = None, staging: bool = False
) -> dict[str, object]:
    """Entry point for generate command."""
    ctx.apply_environment()
    if phase is None:
        run_generate_all(staging=staging)
        return {
            "message": "Full generation pipeline completed",
            "phases": [p.value for p in _PHASE_ORDER],
        }
    run_generate_phase(phase, staging=staging)
    return {"message": f"Generation phase {phase.value} completed", "phase": phase.value}
