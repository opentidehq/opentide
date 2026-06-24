"""CI pipeline setup for client repositories."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import structlog

from opentide.ci.models import CiRenderOptions
from opentide.cli.enums import CiPlatform, DetectionPlatform

logger = structlog.get_logger("opentide.cli.services.setup.ci")


@dataclass
class CiSetupOptions:
    """Non-interactive CI setup configuration."""

    path: Path = Path(".")
    ci: CiPlatform = CiPlatform.github
    platforms: list[DetectionPlatform] = field(default_factory=list)
    staging: bool = True
    promotion: bool = True
    promotion_target: str = "PRODUCTION"
    python_version: str = "3.12"
    yes: bool = False


def run_ci_setup(options: CiSetupOptions) -> dict[str, object]:
    """Write CI pipeline files to the target repository."""
    from opentide.cli.services.ci_generator import write_ci

    if options.ci is CiPlatform.none:
        return {"message": "CI setup skipped", "files": []}
    target = options.path.resolve()
    render = CiRenderOptions.from_repo_options(options)
    written = write_ci(target, render)
    logger.info("ci_pipelines_created", detail=str(target), files=written)
    return {
        "message": "CI pipeline generated",
        "path": str(target),
        "ci": options.ci.value,
        "files": written,
    }
