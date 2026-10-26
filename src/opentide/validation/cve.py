"""Backward-compatible CVE validation entrypoint."""

from __future__ import annotations

from opentide.core.logging import get_logger
from opentide.core.progress import report_stage
from opentide.core.registry import Opentide
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.session import run_validation

logger = get_logger(__name__)

THREAT_MODEL_FIELD = "threat"


def run() -> None:
    """Run CVE validation via the shared validation session."""
    report_stage("CVE check")
    logger.info(
        "cve_validation_start",
        detail="Checks whether CVE fields exist in CIRCL Vulnerability-Lookup",
    )
    Opentide.initialise()
    report = run_validation(checks=frozenset({ValidateCheck.cve}))
    if not report.ok:
        for issue in report.errors:
            logger.error("cve_validation_failed", detail=issue.message, uuid=issue.object_uuid)
    else:
        logger.info("cve_validation_passed")


if __name__ == "__main__":
    run()
