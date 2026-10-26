"""Structured CLI output helpers.

A command returns a :class:`CommandResult`; :func:`emit_result` renders it as
one JSON document (``--json``) or as warnings, one outcome line and next steps
(every other mode). See ``docs/internal/cli-experience.md``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, NoReturn

import structlog
from rich.markup import escape

from opentide.cli.context import CliContext
from opentide.cli.ui.contract import (
    COMMAND_FAILED,
    ISSUES_FOUND,
    NOT_RUN,
    SCHEMA_VERSION,
    USAGE_EXIT_CODE,
    USAGE_INVALID_CHOICE,
    Failure,
    NextAction,
    did_you_mean,
)
from opentide.cli.ui.glyphs import can_encode
from opentide.cli.ui.mode import OutputMode, elapsed_ms, get_mode
from opentide.cli.ui.render import (
    outcome_kind,
    render_error,
    render_next_actions,
    render_notes,
    render_outcome,
    render_warnings,
)
from opentide.core.io import dump_json_text
from opentide.core.logging.config import get_console, get_stdout_console, is_json_output

if TYPE_CHECKING:
    from rich.console import Console

logger = structlog.get_logger("opentide.cli.output")

#: Keys :func:`envelope` adds to every ``--json`` document.
ENVELOPE_KEYS = frozenset(
    {"schema_version", "command", "duration_ms", "exit_code", "summary", "next_actions", "failure"}
)

#: Payload fields that tell the reader what to do about a result, and the
#: severity word each one prints under in human output.
REMEDIATION_FIELDS = ("detail", "advice")
_REMEDIATION_LABELS = {"detail": "note", "advice": "help"}


@dataclass(frozen=True)
class CommandResult:
    """A command outcome shared by human and JSON renderers."""

    message: str
    ok: bool = True
    status: str = "completed"
    data: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    exit_code: int = 0
    #: Counts behind the outcome line (``objects``, ``errors``, ``files``, ...).
    summary: dict[str, Any] = field(default_factory=dict)
    next_actions: tuple[NextAction, ...] = ()
    failure: Failure | None = None

    @classmethod
    def from_payload(
        cls, payload: dict[str, Any], *, default_message: str = "Completed successfully"
    ) -> CommandResult:
        """Normalize a service payload, keeping status and exit policy separate.

        Services may also return ``_summary``, ``_next_actions`` (``NextAction``
        or ``{"command", "reason"}`` items), ``_failure_code``,
        ``_failure_argument`` and ``_failure_suggestion``; they are moved into
        the envelope rather than left in the payload.
        """
        data = dict(payload)
        exit_code = int(data.pop("_exit_code", 0))
        message = str(data.pop("message", default_message))
        status = str(data.pop("status", "completed"))
        warnings = tuple(str(item) for item in data.pop("warnings", ()))
        summary = dict(data.pop("_summary", None) or {})
        next_actions = tuple(_next_action(item) for item in data.pop("_next_actions", None) or ())
        failure_code = data.pop("_failure_code", None)
        failure_argument = data.pop("_failure_argument", None)
        failure_suggestion = data.pop("_failure_suggestion", None)
        ok = status != "failed"
        failure = None
        if not ok or exit_code:
            failure = Failure(
                code=str(failure_code or default_failure_code(status)),
                message=str(data.get("error") or message),
                argument=failure_argument,
                suggestion=failure_suggestion,
            )
        # Presentation follows status; exit_code is process policy only.
        return cls(
            message=message,
            ok=ok,
            status=status,
            data=data,
            warnings=warnings,
            exit_code=exit_code,
            summary=summary,
            next_actions=next_actions,
            failure=failure,
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
        return envelope(
            payload,
            exit_code=self.exit_code,
            summary=self.summary,
            next_actions=self.next_actions,
            failure=self.failure,
        )


def default_failure_code(status: str) -> str:
    """``failure.code`` for a non-zero exit whose service named no code of its own."""
    return {"issues": ISSUES_FOUND, "skipped": NOT_RUN}.get(status, COMMAND_FAILED)


def _next_action(item: NextAction | Mapping[str, Any]) -> NextAction:
    if isinstance(item, NextAction):
        return item
    return NextAction(command=str(item["command"]), reason=str(item.get("reason") or ""))


def current_command() -> str:
    """The running command's path without the program name: ``validate query``.

    Empty outside a Click invocation (a library caller, a unit test).
    """
    from typer._click.globals import get_current_context

    return command_path(get_current_context(silent=True))


def command_path(ctx: Any) -> str:
    """``generate docs rules`` for a context, by walking its parents to the root."""
    names: list[str] = []
    while ctx is not None and ctx.parent is not None:
        if ctx.info_name:
            names.append(str(ctx.info_name))
        ctx = ctx.parent
    return " ".join(reversed(names))


def json_command(command: str) -> str:
    """*command* as a JSON reader runs it: ``opentide validate`` → ``opentide --json validate``."""
    words = command.split()
    if words[:1] != ["opentide"] or "--json" in words:
        return command
    return " ".join(["opentide", "--json", *words[1:]])


def envelope(
    payload: Mapping[str, Any],
    *,
    exit_code: int,
    summary: Mapping[str, Any] | None = None,
    next_actions: Sequence[NextAction] = (),
    failure: Failure | None = None,
    command: str | None = None,
) -> dict[str, Any]:
    """Add the contract's keys to *payload*.

    A payload that already holds one of them raises ``ValueError``: a command
    key silently shadowing the envelope would change what scripts read.
    ``failure`` is null exactly when the exit code is 0. A payload that failed
    or exits non-zero without an explicit *failure* gets one built from its
    ``error`` or ``message``, and a non-zero exit always carries an ``error``
    string, the ``message`` unless the payload set its own. Each next action
    reads ``opentide --json ...``, so a JSON reader can run it as given.
    """
    document = dict(payload)
    clashes = sorted(ENVELOPE_KEYS & document.keys())
    if clashes:
        raise ValueError(f"payload already has envelope key(s): {', '.join(clashes)}")
    if failure is None and (exit_code or document.get("ok") is False):
        failure = Failure(
            code=default_failure_code(str(document.get("status", "failed"))),
            message=str(document.get("error") or document.get("message") or ""),
        )
    if exit_code and not document.get("error"):
        document["error"] = str(
            document.get("message") or (failure.message if failure is not None else "")
        )
    additions: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "command": current_command() if command is None else command,
        "duration_ms": elapsed_ms(),
        "exit_code": exit_code,
        "summary": dict(summary or {}),
        "next_actions": [
            NextAction(json_command(action.command), action.reason).to_dict()
            for action in next_actions
        ],
        "failure": None if failure is None else failure.to_dict(),
    }
    document.update(additions)
    return document


_NON_ASCII = re.compile(r"[^\x00-\x7f]")


def print_document(document: Mapping[str, Any]) -> None:
    """Write one finished JSON document to stdout, ending in exactly one newline.

    ``dump_json_text`` already appends the newline; ``print`` would add a
    second, which a JSON-lines reader sees as an empty record. A stdout that
    cannot encode the text (``PYTHONIOENCODING=ascii``) gets every non-ASCII
    character as a ``\\uXXXX`` escape: the same JSON, without a ``UnicodeEncodeError``.
    """
    text = dump_json_text(document, indent=True, default=str)
    if not can_encode(text, sys.stdout):
        text = _NON_ASCII.sub(_json_escape, text)
    sys.stdout.write(text)
    sys.stdout.flush()


def _json_escape(match: re.Match[str]) -> str:
    """``\\uXXXX`` for one character, as a surrogate pair beyond the BMP."""
    code = ord(match.group())
    if code > 0xFFFF:
        code -= 0x10000
        return f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}"
    return f"\\u{code:04x}"


def emit(ctx: CliContext, payload: dict[str, Any], *, exit_code: int = 0) -> None:
    """Emit *payload* with the envelope as JSON, or raise SystemExit for errors."""
    if ctx.json_output:
        print_document(envelope(payload, exit_code=exit_code))
    if exit_code != 0:
        raise SystemExit(exit_code)


def text_mode(ctx: CliContext) -> OutputMode:
    """The mode a non-JSON render uses: never ``json`` or ``mcp`` once ``--json`` is off."""
    mode = get_mode()
    if mode in (OutputMode.JSON, OutputMode.MCP) and not ctx.json_output:
        return OutputMode.PLAIN
    return mode


def emit_result(ctx: CliContext, result: CommandResult) -> None:
    """Render a normalized command result and honor its exit code.

    Human order: warnings, then exactly one outcome line (an ``error:`` line
    for a failure), then its notes and at most three next steps.
    """
    if ctx.json_output:
        print_document(result.payload())
        if result.exit_code:
            raise SystemExit(result.exit_code)
        return

    render_result(
        result,
        stdout=get_stdout_console(),
        stderr=get_console(),
        mode=text_mode(ctx),
        quiet=ctx.quiet,
    )
    if result.exit_code:
        raise SystemExit(result.exit_code)


def render_result(
    result: CommandResult,
    *,
    stdout: Console,
    stderr: Console,
    mode: OutputMode,
    quiet: bool = False,
) -> None:
    """Print *result* as :func:`emit_result` does, to the given consoles; never exit.

    ``opentide tui`` passes one recording console as both, to show a command's
    result exactly as the command prints it.
    """
    notes = [
        (_REMEDIATION_LABELS[name], str(result.data[name]))
        for name in REMEDIATION_FIELDS
        if result.data.get(name)
    ]
    if not quiet:
        render_warnings(stderr, result.warnings)
    kind = outcome_kind(result.status, ok=result.ok)
    if kind == "failed":
        suggestion = result.failure.suggestion if result.failure else None
        if suggestion and repr(suggestion) not in result.message:
            notes.append(("help", f"did you mean {suggestion!r}?"))
        render_error(stderr, result.message, notes=notes, mode=mode)
        if not quiet:
            render_next_actions(stderr, result.next_actions)
    else:
        render_outcome(stdout, kind, result.message)
        if not quiet:
            render_notes(stdout, notes)
            render_next_actions(stdout, result.next_actions)


def emit_error(
    ctx: CliContext,
    message: str,
    *,
    exit_code: int = 1,
    code: str = COMMAND_FAILED,
    argument: str | None = None,
    suggestion: str | None = None,
    next_actions: Sequence[NextAction] = (),
) -> NoReturn:
    """Emit an error and exit. ``error`` stays the message string; ``failure`` adds the code."""
    emit_result(
        ctx,
        CommandResult(
            message=message,
            ok=False,
            status="failed",
            data={"error": message},
            exit_code=exit_code,
            next_actions=tuple(next_actions),
            failure=Failure(code=code, message=message, argument=argument, suggestion=suggestion),
        ),
    )
    raise AssertionError("error result did not exit")


def emit_usage_error(
    ctx: CliContext,
    message: str,
    *,
    argument: str,
    value: str | None = None,
    choices: Iterable[str] = (),
    code: str = USAGE_INVALID_CHOICE,
) -> NoReturn:
    """A usage error the command itself found: exit 2, with the closest valid choice."""
    suggestion = did_you_mean(value, choices) if value is not None else None
    emit_error(
        ctx,
        message,
        exit_code=USAGE_EXIT_CODE,
        code=code,
        argument=argument,
        suggestion=suggestion,
    )


def emit_success(ctx: CliContext, payload: dict[str, Any]) -> None:
    """Emit a success payload."""
    emit_result(ctx, CommandResult.from_payload(payload))


def emit_deprecation(legacy: str, replacement: str) -> None:
    """Warn about a deprecated spelling without corrupting ``--json`` output."""
    if is_json_output():
        logger.warning("cli_command_deprecated", legacy=legacy, use_instead=replacement)
        return
    get_console().print(f"[yellow]DEPRECATED[/] {escape(legacy)}; use {escape(replacement)}.")
