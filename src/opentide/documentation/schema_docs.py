"""Schema documentation export — delegates to Pydantic doc generator."""

from __future__ import annotations

from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)
from opentide.core.registry import OpenTide
from opentide.generation.doc_generator import export_schema_docs


def run() -> None:
    """Export schema documentation from Pydantic models."""
    schema_docs_path = Path(OpenTide.Configurations.Global.Paths.Core.schemas_docs_folder)
    schema_docs_path.mkdir(parents=True, exist_ok=True)

    docs = export_schema_docs()
    for identifier, content in docs.items():
        safe_name = identifier.replace("::", "_")
        output = schema_docs_path / f"{safe_name}.md"
        output.write_text(content, encoding="utf-8")
        logger.info("exported_schema_documentation", identifier=identifier, output=str(output))

    logger.info("exported_all_pydantic_schema_documentation")
