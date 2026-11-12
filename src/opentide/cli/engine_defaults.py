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
implementation. ``tui`` is the first to flip (UC-6.0d, #841).

One kind of run goes to Rust whatever the defaults say: a ``query``,
``validate query`` or ``deploy`` on an installed platform plugin's platform
(UC-4.5b, #835), since only the Rust core has the plugin hook. The root
callback reads :func:`names_other_platform` to know whether a run may be one;
:func:`opentide.cli.engines.plugin_default` decides.

Standard library only, and no imports at all: the root callback reads it on
every run.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

#: The variable that chooses the implementation for every command at once.
ENGINE_ENV = "OPENTIDE_ENGINE"
PYTHON = "python"
RUST = "rust"

#: A command path's default engine when ``OPENTIDE_ENGINE`` is unset or blank;
#: a path that is not here runs Python. Only ``python`` or ``rust``.
#: ``tui`` opens the Rust UI (ratatui) since its Configuration tab was ported
#: (UC-6.0d, #841); ``OPENTIDE_ENGINE=python`` opens the Textual one until the
#: Python implementation is removed (UC-6.2).
DEFAULT_ENGINES: dict[tuple[str, ...], str] = {("tui",): RUST}

#: The built-in platforms (``opentide.plugins.BUILTIN_PLATFORMS``, kept here
#: so the console script imports nothing more): any other ``--platform`` may
#: be a platform plugin's.
BUILTIN_PLATFORMS: frozenset[str] = frozenset(
    {
        "carbon_black_cloud",
        "crowdstrike",
        "defender_for_endpoint",
        "elastic",
        "harfanglab",
        "sentinel",
        "sentinel_one",
        "splunk",
        "sysdig",
    }
)


def platform_values(options: Sequence[str]) -> list[str]:
    """The values of every ``--platform`` in *options* (``--platform x`` and ``--platform=x``)."""
    values: list[str] = []
    for index, token in enumerate(options):
        if token == "--platform" and index + 1 < len(options):
            values.append(options[index + 1])
        elif token.startswith("--platform="):
            values.append(token.partition("=")[2])
    return values


def names_other_platform(args: Sequence[str]) -> bool:
    """Whether *args* name a ``--platform`` that is not built in, before any ``--``.

    Such a run may be a platform plugin's, which the default engine hands to
    Rust (:func:`opentide.cli.engines.plugin_default`). Reads the arguments
    alone: no entry point is looked up.
    """
    options = args[: args.index("--")] if "--" in args else args
    return any(name not in BUILTIN_PLATFORMS for name in platform_values(options))


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
