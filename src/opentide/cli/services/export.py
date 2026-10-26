"""Export services for the CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from opentide.cli.enums import ExportTarget
from opentide.cli.services.generation import generation_result, generation_step, phase_failure
from opentide.generation.errors import GenerationPhaseError, failing_phase
from opentide.registry.catalogue import with_nested_object_warning

logger = structlog.get_logger("opentide.cli.services.export")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext


def run_export_target(target: ExportTarget) -> None:
    """Run a single export target."""
    if target is ExportTarget.navigator:
        from opentide.export import attack_navigator_layer

        attack_navigator_layer.run()
        return
    if target is ExportTarget.objects:
        from opentide.export.table_export import TableExporter

        TableExporter().run()
        return
    if target is ExportTarget.revisions:
        from opentide.export.revisions_export import run as export_revisions

        export_revisions()
        return
    raise ValueError(f"Unknown export target: {target}")


def run_playbook_map_export() -> None:
    """Run legacy playbook-map export (deprecated)."""
    from opentide.export.playbook_map import run as export_playbook_map

    export_playbook_map()


def run_export(ctx: CliContext, *, target: ExportTarget) -> dict[str, object]:
    """Entry point for export command."""
    from opentide.cli.ui.progress import Checklist

    ctx.apply_environment()
    try:
        with (
            Checklist(total=1) as checklist,
            generation_step(checklist, f"exports {target.value}"),
            failing_phase("exports"),
        ):
            run_export_target(target)
    except GenerationPhaseError as exc:
        return {**phase_failure(exc), "target": target.value}
    return with_nested_object_warning(generation_result(checklist, target=target.value))
