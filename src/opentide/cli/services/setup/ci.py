"""CI pipeline setup for client repositories."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import structlog

from opentide.ci.discovery import discover_enabled_platforms
from opentide.ci.models import CiRenderOptions
from opentide.cli.enums import CiPlatform

logger = structlog.get_logger("opentide.cli.services.setup.ci")

_NO_PLATFORMS_WARNING = (
    "No enabled platforms found under .opentide/configurations/platforms/. "
    "Run `opentide setup platforms` (e.g. `--sentinel`) before `setup ci` so "
    "validate query jobs are included in the generated pipeline."
)


@dataclass
class CiSetupOptions:
    """Non-interactive CI setup configuration."""

    path: Path = Path(".")
    ci: CiPlatform = CiPlatform.github
    staging: bool = True
    promotion: bool = True
    promotion_target: str = "PRODUCTION"
    python_version: str = "3.12"
    explorer_pages: bool = False
    yes: bool = False


def run_ci_setup(options: CiSetupOptions) -> dict[str, object]:
    """Write CI pipeline files to the target repository."""
    from opentide.cli.services.ci_generator import write_ci

    if options.ci is CiPlatform.none:
        return {"message": "CI setup skipped", "files": []}
    target = options.path.resolve()
    platform_ids = discover_enabled_platforms(target)
    warnings: list[str] = []
    if not platform_ids:
        warnings.append(_NO_PLATFORMS_WARNING)
        logger.warning("ci_platforms_missing", detail=str(target), warnings=warnings)
    render = CiRenderOptions.from_repo_options(options, platform_ids)
    written = write_ci(target, render)
    logger.info(
        "ci_pipelines_created",
        detail=str(target),
        files=written,
        platforms=platform_ids,
    )
    result: dict[str, object] = {
        "message": "CI pipeline generated",
        "path": str(target),
        "ci": options.ci.value,
        "platforms": platform_ids,
        "files": written,
    }
    if warnings:
        result["warnings"] = warnings
    return result
