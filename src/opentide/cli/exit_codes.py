"""CI-aware exit code helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentide.validation.issues import ValidationReport


@dataclass(frozen=True)
class CiOutcome:
    """Exit policy for a validation or deployment run.

    ``failed`` drives presentation status. ``exit_code`` is process policy
    (``0`` success, ``1`` failure). Warnings never invent magic exit codes.
    """

    exit_code: int
    failed: bool
    warned: bool


def validation_outcome(*, failed: bool, warned: bool, strict: bool = False) -> CiOutcome:
    """Grade a run from what it found: errors fail it; warnings fail it under *strict*."""
    if failed:
        return CiOutcome(exit_code=1, failed=True, warned=warned)
    if not warned:
        return CiOutcome(exit_code=0, failed=False, warned=False)
    return CiOutcome(exit_code=1 if strict else 0, failed=strict, warned=True)


def report_outcome(report: ValidationReport, *, strict: bool = False) -> CiOutcome:
    """Grade a validation report: an issue fails it; a warning ``--strict`` counts fails it then.

    A disabled platform's block (``platform_not_enabled``) is reported, never failed.
    """
    from opentide.validation.disabled_platforms import STRICT_EXEMPT_WARNINGS

    warned = any(warning.code not in STRICT_EXEMPT_WARNINGS for warning in report.warnings)
    return validation_outcome(failed=not report.ok, warned=warned, strict=strict)


def deployment_outcome() -> CiOutcome:
    """Grade a deployment run without interrupting result rendering."""
    warned = bool(os.environ.get("DEPLOYMENT_WARNING_RAISED"))
    if os.environ.get("DEPLOYMENT_ERROR_RAISED"):
        return CiOutcome(exit_code=1, failed=True, warned=warned)
    return CiOutcome(exit_code=0, failed=False, warned=warned)


def deployment_exit_code() -> int:
    """Return the deployment exit code without interrupting result rendering."""
    return deployment_outcome().exit_code


def exit_on_deployment_errors() -> None:
    """Raise on deployment errors recorded in environment."""
    if os.environ.get("DEPLOYMENT_ERROR_RAISED"):
        raise SystemExit(1)
