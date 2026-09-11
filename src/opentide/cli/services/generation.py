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

# User-visible outputs first, then framework internals. Extract is opt-in only.
_PHASE_ORDER: tuple[str, ...] = (
    "docs",
    "exports",
    "vocabs",
    "templates",
    "schemas",
    "snippets",
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
        from opentide.generation.vscode_snippets import run as generate_snippets

        emit_section("VS Code snippet generation")
        generate_snippets()
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
    if phase == "explorer":
        from opentide.export.explorer_export import run as export_explorer

        emit_section("Explorer export generation")
        export_explorer()
        return
    if phase == "inflight":
        from opentide.indexing.inflight import run as generate_inflight

        emit_section("Inflight preview shard generation")
        return generate_inflight()
    if phase == "inflight-prune":
        from opentide.indexing.inflight import run_prune as prune_inflight

        emit_section("Inflight preview shard prune")
        return prune_inflight()
    if phase == "docs":
        from opentide.documentation.cli import run as run_docs

        emit_section("Documentation generation")
        run_docs()
        return
    raise ValueError(f"Unknown generation phase: {phase}")


def run_generate_docs(
    *,
    output: str | None = None,
    flavor: str | None = None,
    rules: bool = False,
    threats: bool = False,
    objectives: bool = False,
    changed: bool = False,
    scope: str | None = None,
) -> dict[str, object]:
    from opentide.documentation.cli import run as run_docs
    from opentide.documentation.types import DocumentScope

    emit_section("Documentation generation")
    if changed and (scope is not None or rules or threats or objectives):
        raise ValueError("--changed cannot be combined with scoped docs generation")
    if scope == DocumentScope.index.value:
        return run_docs(scope=scope, output=output, flavor=flavor, changed=changed)
    if rules:
        return run_docs(
            scope=DocumentScope.rules.value,
            output=output,
            flavor=flavor,
            changed=changed,
        )
    if threats:
        return run_docs(
            scope=DocumentScope.threats.value,
            output=output,
            flavor=flavor,
            changed=changed,
        )
    if objectives:
        return run_docs(
            scope=DocumentScope.objectives.value,
            output=output,
            flavor=flavor,
            changed=changed,
        )
    if scope:
        return run_docs(scope=scope, output=output, flavor=flavor, changed=changed)
    return run_docs(output=output, flavor=flavor, changed=changed)


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
