"""CI-aware exit code helpers."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class CiOutcome:
    """Exit policy for a validation or deployment run.

    ``failed`` drives presentation status. ``exit_code`` is process policy and
    may still carry legacy GitLab soft-failure ``19`` until that path is removed.
    """

    exit_code: int
    failed: bool
    warned: bool


def _is_gitlab() -> bool:
    from opentide.deployment import CIEnvironment

    return CIEnvironment().environment is CIEnvironment.CIPlatforms.GitlabCI


def exit_on_validation_warnings() -> None:
    """Mirror Orchestration/validate.py GitLab soft-fail behaviour."""
    if not os.environ.get("VALIDATION_WARNING_RAISED"):
        return
    from opentide.deployment import CIEnvironment

    environment = CIEnvironment().environment
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        sys.exit(19)


def validation_outcome(*, strict: bool = False) -> CiOutcome:
    """Grade a validation run without interrupting result rendering."""
    warned = bool(os.environ.get("VALIDATION_WARNING_RAISED"))
    if os.environ.get("VALIDATION_ERROR_RAISED"):
        return CiOutcome(exit_code=1, failed=True, warned=warned)
    if not warned:
        return CiOutcome(exit_code=0, failed=False, warned=False)
    if _is_gitlab():
        return CiOutcome(exit_code=19, failed=False, warned=True)
    return CiOutcome(exit_code=1 if strict else 0, failed=strict, warned=True)


def validation_exit_code(*, strict: bool = False) -> int:
    """Return the validation exit code without interrupting result rendering."""
    return validation_outcome(strict=strict).exit_code


def exit_on_deployment_warnings() -> None:
    """Mirror Orchestration/deploy.py GitLab soft-fail behaviour."""
    if not os.environ.get("DEPLOYMENT_WARNING_RAISED"):
        return
    from opentide.deployment import CIEnvironment

    environment = CIEnvironment().environment
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        sys.exit(19)


def deployment_outcome() -> CiOutcome:
    """Grade a deployment run without interrupting result rendering."""
    warned = bool(os.environ.get("DEPLOYMENT_WARNING_RAISED"))
    if os.environ.get("DEPLOYMENT_ERROR_RAISED"):
        return CiOutcome(exit_code=1, failed=True, warned=warned)
    if not warned:
        return CiOutcome(exit_code=0, failed=False, warned=False)
    if _is_gitlab():
        return CiOutcome(exit_code=19, failed=False, warned=True)
    return CiOutcome(exit_code=0, failed=False, warned=True)


def deployment_exit_code() -> int:
    """Return the deployment exit code without interrupting result rendering."""
    return deployment_outcome().exit_code


def exit_on_validation_errors() -> None:
    """Raise on validation errors recorded in environment."""
    if os.environ.get("VALIDATION_ERROR_RAISED"):
        raise SystemExit(1)


def exit_on_deployment_errors() -> None:
    """Raise on deployment errors recorded in environment."""
    if os.environ.get("DEPLOYMENT_ERROR_RAISED"):
        raise SystemExit(1)
