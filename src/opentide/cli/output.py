"""Structured CLI output helpers."""

from __future__ import annotations

import json
from typing import Any

from opentide.cli.context import CliContext


def emit(ctx: CliContext, payload: dict[str, Any], *, exit_code: int = 0) -> None:
    """Emit machine-readable JSON or raise SystemExit for errors."""
    if ctx.json_output:
        print(json.dumps(payload, indent=2, default=str))
    if exit_code != 0:
        raise SystemExit(exit_code)


def emit_error(ctx: CliContext, message: str, *, exit_code: int = 1) -> None:
    """Emit an error and exit."""
    if ctx.json_output:
        emit(ctx, {"ok": False, "error": message}, exit_code=exit_code)
    else:
        from opentide.core.logging import log

        log("FATAL", message)
        raise SystemExit(exit_code)


def emit_success(ctx: CliContext, payload: dict[str, Any]) -> None:
    """Emit a success payload."""
    if ctx.json_output:
        emit(ctx, {"ok": True, **payload})
    else:
        from opentide.core.logging import log

        log("SUCCESS", payload.get("message", "Completed successfully"))
