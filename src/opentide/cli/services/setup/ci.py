"""CI pipeline setup for client repositories."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

import structlog
import yaml

from opentide.ci.discovery import discover_enabled_platforms
from opentide.ci.models import CiRenderOptions
from opentide.cli.enums import CiPlatform
from opentide.cli.services.setup.promotion import (
    plan_promotion_override,
    write_promotion_override,
)

logger = structlog.get_logger("opentide.cli.services.setup.ci")

_NO_PLATFORMS_WARNING = (
    "No enabled platforms found under .opentide/configurations/platforms/. "
    "Run `opentide setup platforms` (e.g. `--sentinel`) before `setup ci` so "
    "validate query jobs are included in the generated pipeline."
)

GITLAB_DEFAULT_BRANCH = "$CI_DEFAULT_BRANCH"
FALLBACK_DEFAULT_BRANCH = "main"

_BRANCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")


@dataclass
class CiSetupOptions:
    """Non-interactive CI setup configuration."""

    path: Path = Path(".")
    ci: CiPlatform = CiPlatform.github
    staging: bool = True
    #: ``None`` keeps the repository's ``[promotion]`` setting.
    promotion: bool | None = None
    promotion_target: str | None = None
    python_version: str = "3.12"
    explorer_pages: bool = False
    inflight: bool = True
    #: ``None`` detects it from the target repository.
    default_branch: str | None = None
    yes: bool = False


def is_valid_branch_name(name: str) -> bool:
    """Whether *name* can be rendered into the generated pipelines.

    The branch is written unquoted into YAML lists, GitHub expressions, Azure
    conditions and shell commands. Git accepts names that break those (spaces,
    ``$``, quotes) and names YAML reads as another type (``2024``, ``on``).
    """
    return _BRANCH_NAME.fullmatch(name) is not None and yaml.safe_load(name) == name


def _git_stdout(cwd: Path, *args: str) -> str:
    try:
        done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)
    except OSError:
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def detect_default_branch(path: Path) -> str:
    """The branch GitHub and Azure inflight jobs fetch and push to.

    ``origin/HEAD`` names the remote's default branch in a clone; without it,
    ``init.defaultBranch``, then ``main``. A target that does not exist yet
    is read from its nearest existing parent, the repository it will join.
    """
    cwd = next(p for p in (path, *path.parents) if p.is_dir())
    remote_head = _git_stdout(cwd, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
    for branch in (
        remote_head.removeprefix("origin/") if remote_head.startswith("origin/") else "",
        _git_stdout(cwd, "config", "--get", "init.defaultBranch"),
    ):
        if is_valid_branch_name(branch):
            return branch
    return FALLBACK_DEFAULT_BRANCH


def run_ci_setup(options: CiSetupOptions) -> dict[str, object]:
    """Write CI pipeline files to the target repository."""
    from opentide.cli.services.ci_generator import write_ci

    if options.ci is CiPlatform.none:
        return {"message": "CI setup skipped", "files": []}
    if options.default_branch is not None and not is_valid_branch_name(options.default_branch):
        raise ValueError(f"Invalid default branch name: {options.default_branch!r}")
    target = options.path.resolve()
    promotion = plan_promotion_override(
        target, enabled=options.promotion, promotion_target=options.promotion_target
    )
    platform_ids = discover_enabled_platforms(target)
    warnings: list[str] = []
    if not platform_ids:
        warnings.append(_NO_PLATFORMS_WARNING)
        logger.warning("ci_platforms_missing", detail=str(target), warnings=warnings)
    if options.ci is CiPlatform.gitlab:
        branch = GITLAB_DEFAULT_BRANCH
        if options.default_branch is not None:
            warnings.append(
                f"GitLab pipelines publish to {GITLAB_DEFAULT_BRANCH}; --default-branch is ignored."
            )
            logger.warning("ci_default_branch_ignored", detail=options.default_branch)
    else:
        branch = options.default_branch or detect_default_branch(target)
    render = CiRenderOptions.from_repo_options(
        replace(options, default_branch=branch), platform_ids
    )
    written = write_ci(target, render)
    if promotion is not None:
        written.extend(write_promotion_override(target, promotion))
    logger.debug(
        "ci_pipelines_created",
        detail=str(target),
        files=written,
        platforms=platform_ids,
        default_branch=branch,
    )
    result: dict[str, object] = {
        "message": "CI pipeline generated",
        "path": str(target),
        "ci": options.ci.value,
        "platforms": platform_ids,
        "default_branch": branch,
        "files": written,
    }
    if warnings:
        result["warnings"] = warnings
    return result
