"""Structured CLI output helpers."""

from __future__ import annotations

from typing import Any

import structlog

from opentide.cli.context import CliContext
from opentide.core.io import dump_json_text
from opentide.core.logging.console import emit_fatal

logger = structlog.get_logger(__name__)


def emit(ctx: CliContext, payload: dict[str, Any], *, exit_code: int = 0) -> None:
    """Emit machine-readable JSON or raise SystemExit for errors."""
    if ctx.json_output:
        print(dump_json_text(payload, indent=True, default=str))
    if exit_code != 0:
        raise SystemExit(exit_code)


def emit_error(ctx: CliContext, message: str, *, exit_code: int = 1) -> None:
    """Emit an error and exit."""
    if ctx.json_output:
        emit(ctx, {"ok": False, "error": message}, exit_code=exit_code)
    else:
        logger.critical("fatal_error", error=message)
        emit_fatal(message)
        raise SystemExit(exit_code)


def emit_success(ctx: CliContext, payload: dict[str, Any]) -> None:
    """Emit a success payload."""
    if ctx.json_output:
        emit(ctx, {"ok": True, **payload})
    else:
        logger.info(
            "step_completed",
            detail=payload.get("message", "Completed successfully"),
        )
