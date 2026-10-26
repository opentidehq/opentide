"""The data every renderer reads: failures, next actions, and the JSON envelope keys.

Kept free of Rich and Typer so services, the MCP server and tests can build
these without loading a terminal stack.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

#: Bumped only when an existing envelope key changes meaning, which the
#: contract forbids; new keys are additive and keep this at 1.
SCHEMA_VERSION = 1

#: ``failure.code`` for usage errors. All exit 2.
USAGE_UNKNOWN_COMMAND = "usage_unknown_command"
USAGE_UNKNOWN_OPTION = "usage_unknown_option"
USAGE_INVALID_CHOICE = "usage_invalid_choice"
USAGE_INVALID_VALUE = "usage_invalid_value"
USAGE_MISSING_OPTION = "usage_missing_option"
USAGE_NEEDS_INPUT = "usage_needs_input"
USAGE_ERROR = "usage_error"
#: ``validate --watch`` where no terminal shows it: ``json``, ``agent`` or ``mcp`` mode.
USAGE_WATCH_NEEDS_TTY = "usage_watch_needs_tty"

#: ``failure.code`` when a command names no more specific code: it failed,
#: it found issues it was asked to fail on (``--strict``), or it did not run.
COMMAND_FAILED = "command_failed"
ISSUES_FOUND = "issues_found"
NOT_RUN = "not_run"

#: ``failure.code`` when a workspace configuration file does not parse. It is
#: also the code of the diagnostic that points at the file.
CONFIG_PARSE = "config_parse"

#: Exit code of every usage error.
USAGE_EXIT_CODE = 2


@dataclass(frozen=True)
class NextAction:
    """A command worth running next, and why. Rendered after the outcome line."""

    command: str
    reason: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"command": self.command, "reason": self.reason}


@dataclass(frozen=True)
class Failure:
    """Why a command failed, for a program to branch on.

    ``code`` is stable snake_case. ``argument`` names the input at fault
    (``--type``, ``valdate``) and ``suggestion`` the closest valid value.
    ``crash_log`` is reserved for unexpected exceptions.
    """

    code: str
    message: str
    argument: str | None = None
    suggestion: str | None = None
    crash_log: str | None = None

    @property
    def is_usage(self) -> bool:
        return self.code.startswith("usage_")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "argument": self.argument,
            "suggestion": self.suggestion,
            "crash_log": self.crash_log,
        }


#: Separators a typo may add, drop or swap: ``attack-pattern``, ``attack_pattern``.
_SEPARATORS = re.compile(r"[\s_-]+")


def _fold(text: str) -> str:
    """*text* without case or separators, so ``RULE`` and ``rule`` compare equal."""
    return _SEPARATORS.sub("", text).casefold()


def did_you_mean(value: str, choices: Iterable[str]) -> str | None:
    """The valid choice closest to *value*, or ``None`` when nothing is close.

    A choice that differs only in case or separators wins outright (``RULE`` →
    ``rule``); otherwise difflib compares the lower-cased spellings and the
    original spelling of the closest one is returned.
    """
    options = list(dict.fromkeys(choices))
    folded = _fold(value)
    for choice in options:
        if folded and _fold(choice) == folded:
            return choice
    lowered = {choice.casefold(): choice for choice in reversed(options)}
    matches = difflib.get_close_matches(value.casefold(), list(lowered), n=1, cutoff=0.6)
    return lowered[matches[0]] if matches else None
