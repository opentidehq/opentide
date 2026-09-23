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
    promotion: bool = True
    promotion_target: str = "PRODUCTION"
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


def _repository_dir(path: Path) -> Path:
    """A target that does not exist yet is read from the repository it will join."""
    return next(p for p in (path, *path.parents) if p.is_dir())


def _local_branches(cwd: Path) -> set[str]:
    refs = _git_stdout(cwd, "for-each-ref", "--format=%(refname)", "refs/heads/")
    return {ref.removeprefix("refs/heads/") for ref in refs.splitlines()}


def _detect_default_branch(path: Path) -> tuple[str, str]:
    """``(branch, source)``, where *source* names the setting that supplied it."""
    cwd = _repository_dir(path)
    remote_head = _git_stdout(cwd, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
    remote_default = (
        remote_head.removeprefix("origin/") if remote_head.startswith("origin/") else ""
    )
    for source, branch in (
        ("origin/HEAD", remote_default),
        ("HEAD", _git_stdout(cwd, "symbolic-ref", "--quiet", "--short", "HEAD")),
        ("init.defaultBranch", _git_stdout(cwd, "config", "--get", "init.defaultBranch")),
    ):
        if is_valid_branch_name(branch):
            return branch, source
    return FALLBACK_DEFAULT_BRANCH, "fallback"


def detect_default_branch(path: Path) -> str:
    """The branch GitHub and Azure inflight jobs fetch and push to.

    ``origin/HEAD`` names the remote's default branch in a clone. Without it,
    the checked-out branch comes before ``init.defaultBranch``: that setting is
    a per-user default for *new* repositories and says nothing about one made
    with ``git init -b trunk``. It still predicts the branch of a target
    outside any repository. ``main`` comes last.
    """
    return _detect_default_branch(path)[0]


def _default_branch_warnings(path: Path, branch: str, source: str) -> list[str]:
    """Flag a detected branch that is likely not the one that deploys."""
    local = _local_branches(_repository_dir(path))
    if source == "fallback" and branch not in local:
        logger.warning("ci_default_branch_missing", detail=branch)
        return [
            f"Found no origin/HEAD, checked-out branch or init.defaultBranch; the pipeline "
            f"targets {branch!r}, which is not a branch of this repository. "
            "Re-run with --default-branch <branch>."
        ]
    if source == "HEAD" and local - {branch}:
        logger.warning("ci_default_branch_guessed", detail=branch)
        return [
            f"origin/HEAD is not set, so the pipeline targets the checked-out branch {branch!r}. "
            "Re-run with --default-branch <branch> if another branch deploys."
        ]
    return []


def run_ci_setup(options: CiSetupOptions) -> dict[str, object]:
    """Write CI pipeline files to the target repository."""
    from opentide.cli.services.ci_generator import write_ci

    if options.ci is CiPlatform.none:
        return {"message": "CI setup skipped", "files": []}
    if options.default_branch is not None and not is_valid_branch_name(options.default_branch):
        raise ValueError(f"Invalid default branch name: {options.default_branch!r}")
    target = options.path.resolve()
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
    elif options.default_branch is not None:
        branch = options.default_branch
    else:
        branch, source = _detect_default_branch(target)
        warnings.extend(_default_branch_warnings(target, branch, source))
    render = CiRenderOptions.from_repo_options(
        replace(options, default_branch=branch), platform_ids
    )
    written = write_ci(target, render)
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
