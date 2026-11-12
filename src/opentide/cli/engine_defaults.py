"""Which implementation runs a command when ``OPENTIDE_ENGINE`` is unset (plan §7, #822).

The rollout of a command's Rust implementation, one command at a time:

1. It runs Python by default, and ``OPENTIDE_ENGINE=compare`` (CI's golden
   comparison, and users who opt in) runs both for one release.
2. With zero differences for that release, its default flips here to
   ``rust``, with a changelog entry. ``OPENTIDE_ENGINE=python`` still runs
   the Python implementation for one more release: the escape hatch.
3. The release after, the Python implementation is deleted.

A command flips only when it is in :data:`opentide.cli.engines.RUST_COMMANDS`
(the CLI), or, for the SDK and MCP surfaces that return its result
(``run_validation``, ``validation_report``), when the library has its Rust
implementation. ``mcp start`` flipped with UC-6.0c (#841): the Rust server
answers every tool and resource.

Standard library only, and no imports at all: the root callback reads it on
every run.
"""

from __future__ import annotations

from collections.abc import Mapping

#: The variable that chooses the implementation for every command at once.
ENGINE_ENV = "OPENTIDE_ENGINE"
PYTHON = "python"
RUST = "rust"

#: A command path's default engine when ``OPENTIDE_ENGINE`` is unset or blank;
#: a path that is not here runs Python. Only ``python`` or ``rust``.
DEFAULT_ENGINES: dict[tuple[str, ...], str] = {("mcp", "start"): RUST}


def default_engine(words: tuple[str, ...]) -> str:
    """The engine that runs *words* (a command path) when ``OPENTIDE_ENGINE`` is unset."""
    return DEFAULT_ENGINES.get(tuple(words), PYTHON)


def selected(words: tuple[str, ...], env: Mapping[str, str]) -> str:
    """The engine that runs *words*: ``OPENTIDE_ENGINE`` as written, else the default."""
    return env.get(ENGINE_ENV, "").strip() or default_engine(words)


def any_default(words: tuple[str, ...]) -> bool:
    """Whether a command that starts with *words* defaults to something other than Python.

    The root callback's cheap test before it loads the dispatcher: *words* are
    the command line's leading words, which may run past the command path
    into its arguments.
    """
    return any(
        engine != PYTHON and tuple(words[: len(path)]) == path
        for path, engine in DEFAULT_ENGINES.items()
    )
