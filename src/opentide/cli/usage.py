"""Click usage errors rendered through the output contract.

Typer prints a usage error as a Rich panel on stderr, whatever ``--json``
says. :func:`render_usage_error` prints the same error as one JSON document in
``json`` mode, and as an ``error:`` line with a ``help:`` suggestion
otherwise. Exit code 2 either way.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from typer import _click

from opentide.cli.ui.contract import (
    USAGE_ERROR,
    USAGE_EXIT_CODE,
    USAGE_INVALID_CHOICE,
    USAGE_INVALID_VALUE,
    USAGE_MISSING_OPTION,
    USAGE_UNKNOWN_COMMAND,
    USAGE_UNKNOWN_OPTION,
    Failure,
    did_you_mean,
)
from opentide.cli.ui.mode import OutputMode, get_mode

_NO_SUCH_COMMAND = re.compile(r"^No such command '(?P<name>.*?)'\.")
#: Typer appends its own suggestion to the message; the contract carries it in
#: ``failure.suggestion`` and a ``help:`` line instead.
_TYPER_SUGGESTION = re.compile(r"\.? Did you mean .*\?$")
_CHOICE_VALUE = re.compile(r"^'(?P<value>.*?)' is not ")
#: Typer lists the choices of a missing option one per line: ``Choose from:\n\ta,\n\tb``.
_CHOOSE_FROM = re.compile(r"\.?\s*Choose from:\s*(?P<choices>.*)$", re.DOTALL)
_LINE_BREAK = re.compile(r"\s*\n\s*")


def _choose_from(choices: Sequence[str]) -> str:
    return "choose from " + ", ".join(choices)


def one_line(message: str) -> str:
    """*message* on one line, Typer's choice list folded into ``: choose from a, b``."""
    match = _CHOOSE_FROM.search(message)
    if match:
        choices = [part.strip() for part in match["choices"].split(",") if part.strip()]
        message = f"{message[: match.start()]}: {_choose_from(choices)}."
    return _LINE_BREAK.sub(" ", message).strip()

#: Commands people type that are root options: the option, and the ``help:`` line.
_ROOT_OPTION_COMMANDS: dict[str, tuple[str, str]] = {
    word: (
        "--install-completion",
        "did you mean 'opentide --install-completion'? "
        "'opentide --show-completion' prints the script instead",
    )
    for word in ("completion", "completions", "install-completion")
} | {
    "show-completion": (
        "--show-completion",
        "did you mean 'opentide --show-completion'?",
    ),
}


def _param_label(param: Any) -> str | None:
    if param is None:
        return None
    opts = [opt for opt in getattr(param, "opts", ()) if opt.startswith("-")]
    return opts[0] if opts else str(param.name)


def _choices(param: Any) -> Sequence[str]:
    choices = getattr(getattr(param, "type", None), "choices", None) or ()
    return [str(getattr(choice, "value", choice)) for choice in choices]


def _commands(ctx: Any) -> list[str]:
    command = getattr(ctx, "command", None)
    lister = getattr(command, "list_commands", None)
    return list(lister(ctx)) if callable(lister) else []


def describe(error: _click.exceptions.UsageError) -> Failure:
    """The ``failure`` object for a Click usage error."""
    if isinstance(error, _click.exceptions.NoSuchOption):
        possibilities = list(error.possibilities or ())
        return Failure(
            code=USAGE_UNKNOWN_OPTION,
            message=error.message,
            argument=error.option_name,
            suggestion=did_you_mean(error.option_name, possibilities)
            or (possibilities[0] if possibilities else None),
        )
    if isinstance(error, _click.exceptions.MissingParameter):
        return Failure(
            code=USAGE_MISSING_OPTION,
            message=one_line(error.format_message()),
            argument=_param_label(error.param),
        )
    if isinstance(error, _click.exceptions.BadParameter):
        choices = _choices(error.param)
        if choices:
            match = _CHOICE_VALUE.match(error.message)
            return Failure(
                code=USAGE_INVALID_CHOICE,
                message=one_line(error.format_message()),
                argument=_param_label(error.param),
                suggestion=did_you_mean(match["value"], choices) if match else None,
            )
        return Failure(
            code=USAGE_INVALID_VALUE,
            message=one_line(error.format_message()),
            argument=_param_label(error.param),
        )
    if match := _NO_SUCH_COMMAND.match(error.message):
        name = match["name"]
        option = _ROOT_OPTION_COMMANDS.get(name.lower())
        return Failure(
            code=USAGE_UNKNOWN_COMMAND,
            message=_TYPER_SUGGESTION.sub(".", error.message),
            argument=name,
            suggestion=option[0] if option else did_you_mean(name, _commands(error.ctx)),
        )
    return Failure(
        code=USAGE_ERROR,
        message=one_line(error.format_message()),
        argument=getattr(error, "option_name", None),
    )


def render_usage_error(
    error: _click.exceptions.UsageError, *, mode: OutputMode | None = None
) -> int:
    """Print *error* for the current mode and return the exit code to use."""
    from opentide.cli.output import command_path, envelope, print_document

    failure = describe(error)
    mode = mode or get_mode()
    if mode is OutputMode.JSON:
        document = envelope(
            {
                "error": failure.message,
                "ok": False,
                "status": "failed",
                "message": failure.message,
            },
            exit_code=USAGE_EXIT_CODE,
            failure=failure,
            command=command_path(error.ctx),
        )
        print_document(document)
        return USAGE_EXIT_CODE

    from opentide.cli.ui.render import render_error
    from opentide.core.logging.config import get_console

    notes: list[tuple[str, str]] = []
    option = _ROOT_OPTION_COMMANDS.get(str(failure.argument).lower())
    if failure.code == USAGE_UNKNOWN_COMMAND and option:
        notes.append(("help", option[1]))
    elif failure.suggestion:
        notes.append(("help", f"did you mean {failure.suggestion!r}?"))
    ctx = error.ctx
    if ctx is not None:
        usage = ctx.get_usage().removeprefix("Usage: ")
        notes.append(("usage", usage))
        if ctx.command.get_help_option(ctx) is not None:
            notes.append(("help", f"run '{ctx.command_path} {ctx.help_option_names[0]}'"))
    render_error(get_console(), failure.message, notes=notes, mode=mode)
    return USAGE_EXIT_CODE
