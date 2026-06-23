"""CI-aware exit code helpers."""

from __future__ import annotations

import os
import sys


def exit_on_validation_warnings() -> None:
    """Mirror Orchestration/validate.py GitLab soft-fail behaviour."""
    if not os.environ.get("VALIDATION_WARNING_RAISED"):
        return
    from opentide.deployment import CIEnvironment

    environment = CIEnvironment().environment
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        sys.exit(19)


def exit_on_deployment_warnings() -> None:
    """Mirror Orchestration/deploy.py GitLab soft-fail behaviour."""
    if not os.environ.get("DEPLOYMENT_WARNING_RAISED"):
        return
    from opentide.deployment import CIEnvironment

    environment = CIEnvironment().environment
    if environment is CIEnvironment.CIPlatforms.GitlabCI:
        sys.exit(19)


def exit_on_validation_errors() -> None:
    """Raise on validation errors recorded in environment."""
    if os.environ.get("VALIDATION_ERROR_RAISED"):
        raise SystemExit(1)


def exit_on_deployment_errors() -> None:
    """Raise on deployment errors recorded in environment."""
    if os.environ.get("DEPLOYMENT_ERROR_RAISED"):
        raise SystemExit(1)
