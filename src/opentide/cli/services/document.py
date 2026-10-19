"""Documentation generation services."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from opentide.cli.enums import DocumentScope
from opentide.cli.services.generation import phase_failure
from opentide.core.logging.console import emit_section
from opentide.generation.errors import GenerationPhaseError, failing_phase

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
    emit_section(f"Documentation — {'full pipeline' if scope is None else scope.value}")
    try:
        with failing_phase("docs"):
            if scope is None:
                return run_document_all(output=output, flavor=flavor)
            return run_document_scope(scope, output=output, flavor=flavor)
    except GenerationPhaseError as exc:
        return phase_failure(exc)
