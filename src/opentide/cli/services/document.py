"""Documentation generation services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from opentide.cli.enums import DocumentScope
from opentide.cli.services.generation import generation_result, generation_step, phase_failure
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
    from opentide.cli.ui.progress import Checklist

    ctx.apply_environment()
    try:
        with (
            Checklist(total=1) as checklist,
            generation_step(checklist, "docs", outputs=(output,)) as step,
            failing_phase("docs"),
        ):
            if scope is None:
                result = run_document_all(output=output, flavor=flavor)
            else:
                result = run_document_scope(scope, output=output, flavor=flavor)
            if result.get("status") == "failed":
                step.status = "failed"
    except GenerationPhaseError as exc:
        return phase_failure(exc)
    data: dict[str, Any] = {key: value for key, value in dict(result).items() if key != "message"}
    return {**result, **generation_result(checklist, **data)}
