"""Backward-compatible ID uniqueness validation entrypoint."""

from __future__ import annotations

from opentide.core.logging import get_logger
from opentide.core.logging.console import emit_section
from opentide.core.registry import OpenTide
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.session import run_validation

logger = get_logger(__name__)


def run() -> None:
    """Run ID uniqueness validation via the shared validation session."""
    emit_section("ID Duplication Checks")
    logger.info("id_uniqueness_validation_start")
    OpenTide.initialise()
    report = run_validation(checks=frozenset({ValidateCheck.id_uniqueness}))
    if not report.ok:
        for issue in report.errors:
            logger.error(
                "duplicate_id_found",
                detail=issue.message,
                uuid=issue.object_uuid,
            )
        logger.critical("duplicate_ids_not_allowed")
    else:
        logger.info("no_duplicate_ids_found")


if __name__ == "__main__":
    run()
