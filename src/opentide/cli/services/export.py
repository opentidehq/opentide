"""Export services for the CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentide.cli.enums import ExportTarget
from opentide.core.logging import log

if TYPE_CHECKING:
    from opentide.cli.context import CliContext


def run_export_target(target: ExportTarget) -> None:
    """Run a single export target."""
    if target is ExportTarget.navigator:
        from Engines.export import attack_navigator_layer

        attack_navigator_layer.run()
        return
    if target is ExportTarget.table:
        from Engines.export.table_export import TableExporter

        TableExporter().run()
        return
    if target is ExportTarget.playbook_map:
        from opentide.export.playbook_map import run as generate_playbook_map

        generate_playbook_map()
        return
    raise ValueError(f"Unknown export target: {target}")


def run_export(ctx: CliContext, *, target: ExportTarget) -> dict[str, object]:
    """Entry point for export command."""
    ctx.apply_environment()
    log("TITLE", f"Export — {target.value}")
    run_export_target(target)
    return {"message": f"Export {target.value} completed", "target": target.value}
