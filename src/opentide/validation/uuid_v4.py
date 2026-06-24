"""Backward-compatible UUIDv4 validation entrypoint."""

from __future__ import annotations

from opentide.core.logging import get_logger
from opentide.core.logging.console import emit_section
from opentide.core.registry import OpenTide
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.session import run_validation

logger = get_logger(__name__)


def run() -> None:
    """Run UUID format validation via the shared validation session."""
    emit_section("TIDE Objects UUIDv4 Validation")
    logger.info("uuid_v4_validation_start")
    OpenTide.initialise()
    report = run_validation(checks=frozenset({ValidateCheck.uuid_format}))
    if not report.ok:
        for issue in report.errors:
            logger.error(
                "invalid_uuid",
                detail=issue.message,
                uuid=issue.object_uuid,
            )
        logger.error("uuid_validation_failed", count=len(report.errors))
    else:
        logger.info("uuid_validation_passed")


if __name__ == "__main__":
    run()
