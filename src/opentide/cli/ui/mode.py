"""Who is reading the output: a person, a pipe, an agent, a JSON parser or an MCP host.

The mode is resolved once per command run (see ``docs/internal/cli-experience.md``,
"Output modes") and read through :func:`get_mode`. The first rule that matches wins:

1. ``opentide mcp start`` → ``mcp``
2. ``--json`` → ``json``
3. ``OPENTIDE_OUTPUT`` set to ``json``, ``agent``, ``plain`` or ``human`` → that mode
4. a coding agent is detected → ``agent``
5. stdout is not a TTY, ``NO_COLOR`` or ``--no-color``, ``TERM=dumb``, or CI → ``plain``
6. otherwise → ``human``

This module imports nothing beyond the standard library, so anything can ask
for the mode without paying for Typer or Rich.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import IO, TextIO


class OutputMode(str, Enum):
    """The five output modes. The value is what ``OPENTIDE_OUTPUT`` accepts."""

    HUMAN = "human"
    PLAIN = "plain"
    AGENT = "agent"
    JSON = "json"
    MCP = "mcp"

    def __str__(self) -> str:
        return self.value


#: ``OPENTIDE_OUTPUT`` values. ``mcp`` is not one: only ``mcp start`` runs in it.
OUTPUT_ENV_VALUES = frozenset({"json", "agent", "plain", "human"})

#: Read in this order. ``AI_AGENT`` is the proposed cross-tool standard
#: (agentsmd/agents.md#136) and names the agent; the rest are set by one tool each.
AGENT_VARIABLES = (
    "AI_AGENT",
    "CLAUDECODE",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "CODEX_CI",
    "COPILOT_AGENT",
    "COPILOT_CLI",
    "OPENCODE",
    "AMP_CURRENT_THREAD_ID",
    "AUGMENT_AGENT",
    "CLINE_ACTIVE",
)

#: CI providers whose annotations opentide writes, by the variable each one sets.
CI_PROVIDERS = (
    ("GITHUB_ACTIONS", "github"),
    ("GITLAB_CI", "gitlab"),
    ("TF_BUILD", "azure"),
)

_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})

_mode: OutputMode | None = None
_started = time.perf_counter()


def _is_set(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() not in _FALSE_VALUES


def detect_agent(env: Mapping[str, str] | None = None) -> str | None:
    """The coding agent running this process, or ``None``.

    A hint for presentation only: it never relaxes a confirmation, a ``--yes``
    requirement or a strategy check.
    """
    env = os.environ if env is None else env
    for name in AGENT_VARIABLES:
        if _is_set(env, name):
            return env[name].strip() if name == "AI_AGENT" else name.lower()
    return None


def detect_ci(env: Mapping[str, str] | None = None) -> str | None:
    """The CI provider (``github``, ``gitlab``, ``azure``), ``ci`` for another one, or ``None``."""
    env = os.environ if env is None else env
    for name, provider in CI_PROVIDERS:
        if _is_set(env, name):
            return provider
    return "ci" if _is_set(env, "CI") else None


def _is_tty(stream: IO[str] | None) -> bool:
    try:
        return stream is not None and stream.isatty()
    except (AttributeError, ValueError):
        return False


def resolve_mode(
    *,
    json_flag: bool = False,
    no_color: bool = False,
    command: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
) -> OutputMode:
    """Apply the precedence rules above. *command* holds the leading command words."""
    env = os.environ if env is None else env
    if tuple(command[:2]) == ("mcp", "start"):
        return OutputMode.MCP
    if json_flag:
        return OutputMode.JSON
    requested = env.get("OPENTIDE_OUTPUT", "").strip().lower()
    if requested in OUTPUT_ENV_VALUES:
        return OutputMode(requested)
    if detect_agent(env) is not None:
        return OutputMode.AGENT
    stream = sys.stdout if stdout is None else stdout
    if (
        no_color
        or not _is_tty(stream)
        or bool(env.get("NO_COLOR"))
        or env.get("TERM", "").strip().lower() == "dumb"
        or detect_ci(env) is not None
    ):
        return OutputMode.PLAIN
    return OutputMode.HUMAN


def set_mode(mode: OutputMode) -> OutputMode:
    """Fix the mode for the rest of this command run."""
    global _mode
    _mode = mode
    return mode


def start_clock() -> None:
    """Start timing a command run; ``duration_ms`` counts from here."""
    global _started
    _started = time.perf_counter()


def get_mode() -> OutputMode:
    """The mode of the current command run; resolved from the environment if none was set."""
    return _mode if _mode is not None else resolve_mode()


def reset_mode() -> None:
    """Forget the current mode. For tests and for hosts that run several commands."""
    global _mode
    _mode = None


def elapsed_ms() -> int:
    """Milliseconds since :func:`start_clock` (or import) for this command run."""
    return int((time.perf_counter() - _started) * 1000)


def is_machine_mode(mode: OutputMode | None = None) -> bool:
    """Whether stdout belongs to a parser (``json``) or to JSON-RPC (``mcp``)."""
    return (mode or get_mode()) in (OutputMode.JSON, OutputMode.MCP)
