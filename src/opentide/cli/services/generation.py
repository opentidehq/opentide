"""Generation pipeline services for the CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from opentide.core.index_manager import IndexManager
from opentide.core.logging.console import emit_section
from opentide.core.registry import OpenTide

logger = structlog.get_logger("opentide.cli.services.generation")

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

_PHASE_ORDER: tuple[str, ...] = (
    "vocabs",
    "templates",
    "schemas",
    "snippets",
    "exports",
    "playbook-map",
    "docs",
)


def run_generate_phase(phase: str) -> None:
    """Run a single generation phase."""
    if phase == "vocabs":
        from opentide.indexing.object_vocab import run as generate_object_vocab

        emit_section("Object vocabulary generation")
        generate_object_vocab()
        return
    if phase == "templates":
        from opentide.generation.template import run as generate_templates

        emit_section("Template generation")
        generate_templates()
        IndexManager.reload()
        OpenTide.reload()
        return
    if phase == "schemas":
        from opentide.generation.schema import run as generate_schemas

        emit_section("JSON schema generation")
        generate_schemas()
        IndexManager.reload()
        OpenTide.reload()
        return
    if phase == "snippets":
        from opentide.generation import vscode_snippets

        emit_section("VS Code snippet generation")
        vscode_snippets.run()
        return
    if phase == "exports":
        from opentide.export import attack_navigator_layer
        from opentide.export.revisions_export import run as export_revisions
        from opentide.export.table_export import TableExporter

        emit_section("Export generation")
        attack_navigator_layer.run()
        TableExporter().run()
        export_revisions()
        return
    if phase == "playbook-map":
        from opentide.export.playbook_map import run as generate_playbook_map

        emit_section("Playbook map export")
        generate_playbook_map()
        return
    if phase == "docs":
        from opentide.documentation.cli import run as run_docs

        emit_section("Documentation generation")
        run_docs()
        return
    raise ValueError(f"Unknown generation phase: {phase}")


def run_generate_docs(
    *,
    rules: bool = False,
    threats: bool = False,
    objectives: bool = False,
) -> None:
    from opentide.documentation.cli import run as run_docs
    from opentide.documentation.types import DocumentScope

    emit_section("Documentation generation")
    if rules:
        run_docs(scope=DocumentScope.rules)
        return
    if threats:
        run_docs(scope=DocumentScope.threats)
        return
    if objectives:
        run_docs(scope=DocumentScope.objectives)
        return
    run_docs()


def run_generate_all() -> None:
    """Run the full generation pipeline."""
    for phase in _PHASE_ORDER:
        run_generate_phase(phase)


def run_generate(ctx: CliContext, *, phase: str | None = None) -> dict[str, object]:
    """Entry point for generate command."""
    ctx.apply_environment()
    if phase is None:
        run_generate_all()
        return {"message": "Full generation pipeline completed", "phases": list(_PHASE_ORDER)}
    run_generate_phase(phase)
    return {"message": f"Generation phase {phase} completed", "phase": phase}
