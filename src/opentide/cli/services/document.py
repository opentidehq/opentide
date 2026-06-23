"""Documentation generation services."""

from __future__ import annotations
from typing import TYPE_CHECKING
from opentide.cli.enums import DocumentScope
import structlog
from opentide.core.logging.console import emit_section

logger = structlog.get_logger("opentide.cli.services.document")
if TYPE_CHECKING:
    from opentide.cli.context import CliContext
_SCOPE_RUNNERS: dict[DocumentScope, tuple[str, str]] = {
    DocumentScope.vocabularies: ("opentide.documentation.vocabularies", "run"),
    DocumentScope.metaschemas: ("opentide.documentation.metaschemas", "run"),
    DocumentScope.models: ("opentide.documentation.models", "run"),
    DocumentScope.objectives: ("opentide.documentation.dom", "run"),
    DocumentScope.rules: ("opentide.documentation.mdr", "run"),
    DocumentScope.navigation: ("opentide.documentation.wiki_navigation", "run"),
}


def run_document_scope(scope: DocumentScope) -> None:
    """Run a single documentation scope."""
    import importlib

    module_path, func_name = _SCOPE_RUNNERS[scope]
    module = importlib.import_module(module_path)
    getattr(module, func_name)()


def run_document_all() -> None:
    """Run full documentation pipeline (Orchestration/document.py parity)."""
    for scope in (
        DocumentScope.vocabularies,
        DocumentScope.metaschemas,
        DocumentScope.models,
        DocumentScope.objectives,
        DocumentScope.rules,
        DocumentScope.navigation,
    ):
        emit_section("Documentation — {}")
        run_document_scope(scope)


def run_document(
    ctx: CliContext, *, scope: DocumentScope | None = None, output: str | None = None
) -> dict[str, object]:
    """Entry point for document command."""
    ctx.apply_environment()
    if output is not None:
        import os

        os.environ["DOCUMENTATION_OUTPUT"] = output
    if scope is None:
        run_document_all()
        return {"message": "Full documentation pipeline completed"}
    run_document_scope(scope)
    return {"message": f"Documentation scope {scope.value} completed", "scope": scope.value}
