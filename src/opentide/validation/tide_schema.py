"""Schema validation — Pydantic ValidationSession pipeline."""

from __future__ import annotations

import os
from typing import Any

import structlog

from opentide.core.logging.console import emit_section
from opentide.core.registry import OpenTide
from opentide.validation.errors import format_issues_for_console
from opentide.validation.session import run_validation

logger = structlog.get_logger("opentide.validation.tide_schema")


def _format_stats_table(rows: list[list[Any]]) -> str:
    if not rows:
        return ""
    widths = [max(len(str(row[col])) for row in rows) for col in range(len(rows[0]))]
    lines: list[str] = []
    for row_index, row in enumerate(rows):
        lines.append(" | ".join(str(cell).ljust(widths[col]) for col, cell in enumerate(row)))
        if row_index == 0:
            lines.append("-+-".join("-" * width for width in widths))
    return "\n".join(lines)


def run() -> None:
    emit_section("Pydantic Schema Validation")
    logger.info("validates_all_opentide_objects_via_model_validate")
    OpenTide.initialise()
    report = run_validation()
    stats: dict[str, int] = {}
    overall = 0
    for schema in OpenTide.Index["objects"]:
        count = len(OpenTide.Index["objects"].get(schema, {}))
        stats[schema.upper()] = count
        overall += count
    if report.issues:
        print(format_issues_for_console(report.issues))
        for issue in report.issues:
            logger.critical(
                "fatal_error",
                detail=f"Failed validation for object {issue.object_uuid}",
                arg0=issue.to_legacy_string(),
            )
        logger.critical(
            "failed_schema_validation",
            detail="OpenTide objects currently do not match Pydantic models",
            advice="Review the files before running the validation again",
        )
        os.environ["VALIDATION_ERROR_RAISED"] = "True"
    else:
        statstable = [["Category", "Count"]]
        for key in stats:
            statstable.append([key, stats[key]])
        statstable = _format_stats_table(statstable)
        logger.info("step_completed", detail=f"Successfully verified {overall} OpenTide objects")
        print(statstable)


if __name__ == "__main__":
    run()
