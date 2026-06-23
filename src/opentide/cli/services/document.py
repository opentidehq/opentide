"""Documentation generation services."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from opentide.cli.enums import DocumentScope
from opentide.core.logging.console import emit_section

logger = structlog.get_logger("opentide.cli.services.document")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext


def run_document_scope(
    scope: DocumentScope, *, output: str | None = None, flavor: str | None = None
) -> dict[str, object]:
    """Run a single documentation scope."""
    from opentide.documentation.cli import run

    return run(scope=scope.value, output=output, flavor=flavor)


def run_document_all(*, output: str | None = None, flavor: str | None = None) -> dict[str, object]:
    """Run full documentation pipeline: objects then index."""
    from opentide.documentation.cli import run

    return run(scope=None, output=output, flavor=flavor)


def run_document(
    ctx: CliContext,
    *,
    scope: DocumentScope | None = None,
    output: str | None = None,
    flavor: str | None = None,
) -> dict[str, object]:
    """Entry point for document command."""
    ctx.apply_environment()
    if scope is None:
        emit_section("Documentation — full pipeline")
        return run_document_all(output=output, flavor=flavor)
    emit_section(f"Documentation — {scope.value}")
    return run_document_scope(scope, output=output, flavor=flavor)
