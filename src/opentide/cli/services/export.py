"""Export services for the CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from opentide.cli.enums import ExportTarget
from opentide.core.logging.console import emit_section

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
    ctx.apply_environment()
    emit_section(f"Export — {target.value}")
    run_export_target(target)
    return {"message": f"Export {target.value} completed", "target": target.value}
