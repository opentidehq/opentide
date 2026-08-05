"""Structured CLI output helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, NoReturn

from opentide.cli.context import CliContext
from opentide.core.io import dump_json_text
from opentide.core.logging.config import get_console, get_stdout_console
from opentide.core.logging.console import emit_fatal


@dataclass(frozen=True)
class CommandResult:
    """A command outcome shared by human and JSON renderers."""

    message: str
    ok: bool = True
    status: str = "completed"
    data: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    exit_code: int = 0

    @classmethod
    def from_payload(
        cls, payload: dict[str, Any], *, default_message: str = "Completed successfully"
    ) -> CommandResult:
        """Normalize a service payload, keeping status and exit policy separate."""
        data = dict(payload)
        exit_code = int(data.pop("_exit_code", 0))
        message = str(data.pop("message", default_message))
        status = str(data.pop("status", "completed"))
        warnings = tuple(str(item) for item in data.pop("warnings", ()))
        # Presentation follows status; exit_code is process policy only.
        return cls(
            message=message,
            ok=status != "failed",
            status=status,
            data=data,
            warnings=warnings,
            exit_code=exit_code,
        )

    def payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            **self.data,
            "ok": self.ok,
            "status": self.status,
            "message": self.message,
        }
        if self.warnings:
            payload["warnings"] = list(self.warnings)
        return payload


def emit(ctx: CliContext, payload: dict[str, Any], *, exit_code: int = 0) -> None:
    """Emit machine-readable JSON or raise SystemExit for errors."""
    if ctx.json_output:
        print(dump_json_text(payload, indent=True, default=str))
    if exit_code != 0:
        raise SystemExit(exit_code)


def emit_result(ctx: CliContext, result: CommandResult) -> None:
    """Render a normalized command result and honor its exit code."""
    if ctx.json_output:
        emit(ctx, result.payload(), exit_code=result.exit_code)
        return

    console = get_stdout_console()
    if not result.ok:
        emit_fatal(result.message)
    elif result.status == "skipped":
        console.print(f"[yellow]SKIPPED[/] {result.message}")
    else:
        console.print(f"[bold green]OK[/] {result.message}")
    for warning in result.warnings:
        get_console().print(f"[yellow]WARNING[/] {warning}")
    if result.exit_code:
        raise SystemExit(result.exit_code)


def emit_error(ctx: CliContext, message: str, *, exit_code: int = 1) -> NoReturn:
    """Emit an error and exit."""
    emit_result(
        ctx,
        CommandResult(
            message=message,
            ok=False,
            status="failed",
            data={"error": message},
            exit_code=exit_code,
        ),
    )
    raise AssertionError("error result did not exit")


def emit_success(ctx: CliContext, payload: dict[str, Any]) -> None:
    """Emit a success payload."""
    emit_result(ctx, CommandResult.from_payload(payload))
