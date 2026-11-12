"""``OPENTIDE_ENGINE``: which implementation of a command runs (plan §5.2, #805).

During the move to one Rust core, a command can have two implementations:
the Python one, which every command has and which is the oracle, and a Rust
one. ``OPENTIDE_ENGINE`` chooses, read once per process by the root callback:

- unset or empty: the command's default engine
  (:mod:`opentide.cli.engine_defaults`), Python until its rollout flips it.
- ``python``: the Python implementation, whatever the default (the escape
  hatch for the release after a command's default flips).
- ``rust``: the Rust implementation. A command without one is a usage error,
  ``failure.code`` ``engine_not_ported``, exit 2.
- ``compare``: both, each on its own copy of the workspace, and their exit
  codes, stdout, stderr and the files they wrote are compared with the
  comparator ``cargo xtask compare`` uses (``crates/opentide-compare``). If they
  agree, the Python run's output and exit code are the result; if not, exit 70,
  ``failure.code`` ``engine_mismatch``, and a diff report in the state
  directory whose path the message names. A command without a Rust
  implementation runs Python alone, and so does a run its Rust implementation
  refuses with ``engine_not_ported`` (:data:`REFUSAL_ENV`): one it covers for
  some inputs only, such as ``query`` with ``--rule``.

:data:`RUST_COMMANDS` is the dispatch table: the work items that port a
command add it there. The console script reads it before Typer or anything
else is loaded (:mod:`opentide.cli.launch`), so this module imports only the
standard library's cheapest modules at the top; what ``compare`` needs is
imported where it runs.
"""

from __future__ import annotations

import os
import stat
import sys

from opentide.cli.engine_defaults import (
    BUILTIN_PLATFORMS,
    ENGINE_ENV,
    PYTHON,
    RUST,
    default_engine,
    platform_values,
)

#: ``typing.TYPE_CHECKING`` without importing typing, which the console
#: script would pay for on every Rust run (UC-3.8b, #960); type checkers
#: read it as True.
TYPE_CHECKING = False

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence
    from pathlib import Path
    from typing import Any, NoReturn

    from typer import _click

    from opentide.analysis import CompareRun
    from opentide.cli.context import CliContext

COMPARE = "compare"
#: The values ``OPENTIDE_ENGINE`` accepts.
ENGINES = (PYTHON, RUST, COMPARE)

#: The variable naming the file in which the Rust side of ``compare`` records
#: an ``engine_not_ported`` refusal (``REFUSAL_ENV`` in
#: ``crates/opentide-cli/src/app.rs``): the Rust implementation does not cover
#: this run's input, and the Python run is the result, as for a command with
#: no Rust implementation.
REFUSAL_ENV = "OPENTIDE_ENGINE_REFUSAL"

#: What the workspace copy's path reads as in both runs before they are compared.
WORKSPACE_PLACEHOLDER = "<WS>"


class RustCommand:
    """A command's Rust implementation: the command line that runs it.

    The command's arguments follow *launch*. It runs with ``OPENTIDE_ENGINE``
    set to ``rust`` in its environment.

    *rules* are the extra normalisation rules the command's golden cases opt
    into (``fresh-uuids`` for a command that mints identifiers, ``host-git``
    for one that prints the host's git version): ``compare`` applies them as
    the goldens do. *side_effects* marks a command that reaches outside the
    workspace (a tenant, MISP): ``compare`` refuses it, since both runs would
    reach it and nothing would compare what they did there.

    *requires* names flags (or words: ``generate``'s phases) of which a run
    must carry one for the Rust implementation to cover it (``deploy`` runs in
    Rust with ``--dry-run`` only); a run without any is a command with no
    Rust implementation:
    ``rust`` refuses it with ``engine_not_ported`` and ``compare`` runs
    Python alone. *refuses* names flags a run must carry none of.

    *platforms* names the platforms with a Rust connector (UC-4.2, #832) for
    a command that reaches tenants: a run is covered only when every
    ``--platform`` it names is one of them, and a run that names none is not
    (the platforms it would touch are the workspace's). *platform_scope*
    names the flags under which *platforms* applies (``validate query`` is
    offline, every platform covered, unless it carries ``--live``); empty, it
    applies to every run. The Rust side refuses with ``engine_not_ported``
    any run whose tenants it does not reach, as a second check
    (:data:`REFUSAL_ENV`).

    *offline* names flags under which a run reaches no tenant (``deploy
    --dry-run``): neither *platforms* nor *side_effects* applies to it.

    *plugins* marks a command that runs on a platform plugin (UC-4.5, #835):
    a run whose every ``--platform`` names an installed plugin
    (:func:`plugin_platforms`) is covered whatever *requires* and *platforms*
    say, since only the Rust core has the plugin hook; *refuses* still
    applies.
    """

    __slots__ = (
        "launch",
        "offline",
        "platform_scope",
        "platforms",
        "plugins",
        "refuses",
        "requires",
        "rules",
        "side_effects",
    )

    def __init__(
        self,
        launch: tuple[str, ...],
        rules: tuple[str, ...] = (),
        side_effects: bool = False,
        requires: tuple[str, ...] = (),
        refuses: tuple[str, ...] = (),
        platforms: tuple[str, ...] = (),
        platform_scope: tuple[str, ...] = (),
        offline: tuple[str, ...] = (),
        plugins: bool = False,
    ) -> None:
        self.launch = launch
        self.rules = rules
        self.side_effects = side_effects
        self.requires = requires
        self.refuses = refuses
        self.platforms = platforms
        self.platform_scope = platform_scope
        self.offline = offline
        self.plugins = plugins

    def _key(self) -> tuple[object, ...]:
        return (
            self.launch,
            self.rules,
            self.side_effects,
            self.requires,
            self.refuses,
            self.platforms,
            self.platform_scope,
            self.offline,
            self.plugins,
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RustCommand) and self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __repr__(self) -> str:
        return (
            f"RustCommand(launch={self.launch!r}, rules={self.rules!r}, "
            f"side_effects={self.side_effects!r}, requires={self.requires!r}, "
            f"refuses={self.refuses!r}, platforms={self.platforms!r}, "
            f"platform_scope={self.platform_scope!r}, offline={self.offline!r}, "
            f"plugins={self.plugins!r})"
        )

    def covers(self, args: Sequence[str]) -> bool:
        """Whether the Rust implementation runs the command with *args*."""
        options = args[: args.index("--")] if "--" in args else args
        if any(flag in options for flag in self.refuses):
            return False
        if self.plugin_run(options):
            return True
        if self._uncovered_platforms(options) is not None:
            return False
        return not self.requires or any(flag in options for flag in self.requires)

    def plugin_run(self, args: Sequence[str]) -> bool:
        """Whether every ``--platform`` *args* name is an installed plugin's.

        A run that names none, or names a built-in platform, is not a plugin
        run: those never read the entry points.
        """
        options = args[: args.index("--")] if "--" in args else args
        if not self.plugins:
            return False
        named = platform_values(options)
        if not named or any(name in BUILTIN_PLATFORMS for name in named):
            return False
        installed = plugin_platforms()
        return all(name in installed for name in named)

    def uncovered(self, path: str, args: Sequence[str]) -> str:
        """*path* as a run of *args* it does not cover reads: ``deploy without --dry-run``."""
        options = args[: args.index("--")] if "--" in args else args
        refused = [flag for flag in self.refuses if flag in options]
        if refused:
            return f"{path} with {' and '.join(refused)}"
        platforms = self._uncovered_platforms(options)
        if platforms is not None:
            scope = [flag for flag in self.platform_scope if flag in options]
            where = f"{path} {' '.join(scope)}".rstrip()
            if not platforms:
                return f"{where} without --platform"
            return f"{where} on {', '.join(platforms)}"
        return f"{path} without {' or '.join(self.requires)}"

    def _uncovered_platforms(self, options: Sequence[str]) -> list[str] | None:
        """The platforms *options* name that have no Rust connector (``[]``: none named).

        ``None`` when the run's platforms are covered, or *platforms* does not apply.
        """
        if not self.platforms:
            return None
        if any(flag in options for flag in self.offline):
            return None
        if self.platform_scope and not any(flag in options for flag in self.platform_scope):
            return None
        named = platform_values(options)
        if not named:
            return []
        missing = [name for name in dict.fromkeys(named) if name not in self.platforms]
        return missing or None


def plugin_platforms() -> frozenset[str]:
    """The platform plugins installed: ``opentide.platforms`` entry points that are not built in.

    Read without loading any plugin. Only a run that names a platform outside
    :data:`BUILTIN_PLATFORMS` pays for the lookup.
    """
    from importlib.metadata import entry_points

    return frozenset(
        point.name
        for point in entry_points(group="opentide.platforms")
        if point.name not in BUILTIN_PLATFORMS
    )


#: The platforms with a Rust connector (``crates/opentide-connectors``) whose
#: ``query`` runs on Rust: every platform with a query runner. The REST
#: platforms came with UC-4.2 (#832); Sentinel, Splunk and Carbon Black Cloud,
#: which Python reaches through vendor SDKs, with UC-4.3 (#833). Sysdig has no
#: runner.
RUST_QUERY_PLATFORMS: tuple[str, ...] = (
    "carbon_black_cloud",
    "crowdstrike",
    "defender_for_endpoint",
    "elastic",
    "harfanglab",
    "sentinel",
    "sentinel_one",
    "splunk",
)

#: The platforms whose ``query`` runs on Rust (*platforms* of ``query``'s
#: entry): :data:`RUST_QUERY_PLATFORMS`, and Sysdig, which has no runner and
#: is refused as Python refuses it (``sysdig has no query runner``, UC-6.0d,
#: #841).
RUST_QUERY_ROUTED: tuple[str, ...] = (
    "carbon_black_cloud",
    "crowdstrike",
    "defender_for_endpoint",
    "elastic",
    "harfanglab",
    "sentinel",
    "sentinel_one",
    "splunk",
    "sysdig",
)

#: Commands that host others and apply ``OPENTIDE_ENGINE`` to what they run
#: rather than to themselves: ``serve`` runs each request on the engine its
#: command selects (#822), and the MCP server's read tools do the same. They
#: run under any engine; one that is also in :data:`RUST_COMMANDS` runs its
#: Rust implementation under ``rust`` (``mcp start``, UC-3.7, #829), and its
#: Python one, the host, under ``compare``: an MCP call under ``compare``
#: answers with Python's result and records a Rust difference (#822). ``lsp
#: start`` (UC-3.6b, #947) is one too: an editor's session has one server on
#: stdio, so ``compare`` runs the Python host and ``rust`` the Rust one. So is
#: ``tui``: a full-screen UI cannot run twice to be compared, so ``compare``
#: opens the Rust one (:data:`UNCOMPARED_RUST`), the default since its
#: Configuration tab was ported (UC-6.0d); its refusals and its UI (on
#: ratatui, UC-3.6d, #951) run on Rust.
ENGINE_HOSTS: frozenset[tuple[str, ...]] = frozenset(
    {("serve",), ("mcp", "start"), ("lsp", "start"), ("tui",)}
)

#: Hosts that ``compare`` runs on Rust alone: ``tui``, whose Rust UI is the
#: default (UC-6.0d, #841) and which cannot run twice to be compared.
UNCOMPARED_RUST: frozenset[tuple[str, ...]] = frozenset({("tui",)})

#: The Rust command line compiled into ``opentide._native`` (:mod:`opentide.cli.rust`).
#: ``rust`` runs it in this process (:func:`opentide.cli.rust.run_in_process`);
#: ``compare`` runs this command line as a child, next to Python's.
RUST_CLI: tuple[str, ...] = (sys.executable, "-m", "opentide.cli.rust")

#: Command paths (``("validate",)``, ``("generate", "docs")``) that have a Rust
#: implementation. Every command has its Python one; a path is added here in
#: the change that ports it. ``info`` (every section) and ``rules unreviewed``
#: came with UC-2.4 (#819); ``generate exports`` and its three exports with
#: UC-3.2 (#824); ``generate docs`` and its four scopes with UC-3.2b (#915);
#: ``generate explorer``, ``generate inflight`` and its ``prune``, and ``setup ci``
#: with UC-3.2c (#916); ``deploy --dry-run`` with UC-3.1c (#896): a deploy that
#: sends stays Python's; ``commands``, ``explain``, ``lint`` and ``validate`` with
#: UC-3.5 (#827); offline ``validate query`` with UC-3.5b (#927): ``--live`` stays
#: Python's; ``migrate vocab-scope`` and ``doctor --offline`` with UC-3.5c (#928): a
#: doctor that reaches PyPI and the proxy stays Python's; ``mcp start`` with UC-3.7
#: (#829): the Rust server, which hands the tools and resources it has no
#: implementation of to the Python server's handlers in its own process
#: (``opentide.mcp_server.bridge``); ``setup skills discover`` and ``setup skills
#: show`` with UC-4.1 (#831): the opentidehq/skills catalogue through the connectors'
#: HTTP client; ``setup`` (scripted runs and ``--plan``) and its ``env``, ``hooks``,
#: ``mcp``, ``platforms`` and ``repo`` with UC-3.6 (#828); ``setup vscode``,
#: ``setup --vscode-setup`` and the wizards at a terminal with UC-3.6c (#951);
#: ``setup skills`` (the install), ``setup --skills`` and ``--plugin`` with
#: UC-4.4d (#834): the skill trees through the connectors' HTTP client.
#: ``new threat|objective|rule`` and ``generate`` with phases named
#: (``generate schemas templates``) with UC-3.5d (#933); a bare ``generate``,
#: the full pipeline, with UC-6.0 (#841).
#: ``serve`` with UC-3.8 (#830): the Rust host, which runs every request on
#: Rust in its own process, whatever engine the request names (UC-6.0d, #841).
#: ``lsp start`` with UC-3.6b (#947): the language server hosted by the Rust
#: command line, and ``tui``'s refusals (``usage_tui_needs_tty``); ``tui``'s
#: terminal UI with UC-3.6d (#951), on ratatui.
#: ``query`` on the platforms of :data:`RUST_QUERY_PLATFORMS`, and ``validate
#: query --live`` on every platform, with
#: UC-4.2c (#832): *platforms* routes each run by the ``--platform`` it names.
#: ``query`` on Sentinel, Splunk and Carbon Black Cloud with UC-4.3 (#833).
#: ``validate query --live`` on the six platforms whose tenants check queries
#: with UC-4.6 (#979), and ``deploy`` that sends on every platform: *offline*
#: keeps ``--dry-run`` covered whatever its ``--platform``.
#: ``deploy migrate-state`` and ``doctor``'s network checks (PyPI, the proxy)
#: with UC-4.4 (#834): ``doctor`` no longer requires ``--offline``. With UC-4.4c
#: (#834), the last runs that reached tenants from Python: a rule's query
#: (``query --rule``, ``--file``), and ``deploy`` and ``validate query --live``
#: without ``--platform`` (every platform has a Rust connector, so neither names
#: *platforms*: ``deploy`` sends to the workspace's enabled platforms, and
#: ``validate query --live`` refuses a run that names none, as Python does).
#: ``share`` and its ``push``, ``preview``, ``status``, ``retract`` and
#: ``targets`` over MISP's REST API, and ``generate extract defender`` and
#: ``generate extract elastic`` through their connectors, with UC-4.4b (#834);
#: ``share push --changed`` reading its git diff, and ``generate extract
#: sentinel`` through the Sentinel connector, with UC-4.4e (#834).
#: ``deploy``, ``query`` and ``validate query --live`` on an installed platform
#: plugin's platform run on Rust, the one engine with the plugin hook
#: (*plugins*, UC-4.5, #835), under the default engine too (UC-4.5b:
#: :func:`plugin_default`).
RUST_COMMANDS: dict[tuple[str, ...], RustCommand] = {
    ("commands",): RustCommand(launch=RUST_CLI),
    ("explain",): RustCommand(launch=RUST_CLI),
    ("info",): RustCommand(launch=RUST_CLI),
    ("lint",): RustCommand(launch=RUST_CLI),
    ("validate",): RustCommand(launch=RUST_CLI),
    ("validate", "query"): RustCommand(launch=RUST_CLI, plugins=True),
    ("rules", "unreviewed"): RustCommand(launch=RUST_CLI),
    ("deploy",): RustCommand(
        launch=RUST_CLI, side_effects=True, offline=("--dry-run",), plugins=True
    ),
    ("deploy", "migrate-state"): RustCommand(launch=RUST_CLI),
    ("doctor",): RustCommand(launch=RUST_CLI, rules=("host-git",)),
    ("migrate", "vocab-scope"): RustCommand(launch=RUST_CLI),
    ("generate", "exports"): RustCommand(launch=RUST_CLI),
    ("generate", "exports", "navigator"): RustCommand(launch=RUST_CLI),
    ("generate", "exports", "objects"): RustCommand(launch=RUST_CLI),
    ("generate", "exports", "revisions"): RustCommand(launch=RUST_CLI),
    ("generate", "docs"): RustCommand(launch=RUST_CLI),
    ("generate", "docs", "rules"): RustCommand(launch=RUST_CLI),
    ("generate", "docs", "objectives"): RustCommand(launch=RUST_CLI),
    ("generate", "docs", "threats"): RustCommand(launch=RUST_CLI),
    ("generate", "docs", "index"): RustCommand(launch=RUST_CLI),
    ("generate", "explorer"): RustCommand(launch=RUST_CLI),
    ("generate", "inflight"): RustCommand(launch=RUST_CLI),
    ("generate", "inflight", "prune"): RustCommand(launch=RUST_CLI),
    ("setup", "ci"): RustCommand(launch=RUST_CLI),
    ("setup", "skills", "discover"): RustCommand(launch=RUST_CLI),
    ("setup", "skills", "show"): RustCommand(launch=RUST_CLI),
    ("setup", "skills"): RustCommand(launch=RUST_CLI),
    ("setup",): RustCommand(launch=RUST_CLI),
    ("setup", "env"): RustCommand(launch=RUST_CLI),
    ("setup", "hooks"): RustCommand(launch=RUST_CLI),
    ("setup", "mcp"): RustCommand(launch=RUST_CLI),
    ("setup", "platforms"): RustCommand(launch=RUST_CLI),
    ("setup", "repo"): RustCommand(launch=RUST_CLI),
    ("setup", "vscode"): RustCommand(launch=RUST_CLI),
    ("mcp", "start"): RustCommand(launch=RUST_CLI),
    ("generate",): RustCommand(launch=RUST_CLI),
    ("new", "threat"): RustCommand(launch=RUST_CLI, rules=("fresh-uuids",)),
    ("new", "objective"): RustCommand(launch=RUST_CLI, rules=("fresh-uuids",)),
    ("new", "rule"): RustCommand(launch=RUST_CLI, rules=("fresh-uuids",)),
    ("serve",): RustCommand(launch=RUST_CLI),
    ("lsp", "start"): RustCommand(launch=RUST_CLI),
    ("tui",): RustCommand(launch=RUST_CLI),
    ("query",): RustCommand(
        launch=RUST_CLI, side_effects=True, platforms=RUST_QUERY_ROUTED, plugins=True
    ),
    ("share",): RustCommand(launch=RUST_CLI, side_effects=True, offline=("--dry-run",)),
    ("share", "push"): RustCommand(launch=RUST_CLI, side_effects=True, offline=("--dry-run",)),
    ("share", "preview"): RustCommand(launch=RUST_CLI),
    ("share", "status"): RustCommand(launch=RUST_CLI),
    ("share", "retract"): RustCommand(launch=RUST_CLI, side_effects=True),
    ("share", "targets"): RustCommand(launch=RUST_CLI),
    ("generate", "extract", "defender"): RustCommand(launch=RUST_CLI, side_effects=True),
    ("generate", "extract", "elastic"): RustCommand(launch=RUST_CLI, side_effects=True),
    ("generate", "extract", "sentinel"): RustCommand(launch=RUST_CLI, side_effects=True),
}


def python_launch() -> tuple[str, ...]:
    """The command line that runs this installation's Python CLI."""
    return (sys.executable, "-m", "opentide")


def requested(env: Mapping[str, str] | None = None) -> str:
    """The engine ``OPENTIDE_ENGINE`` names, as written; ``python`` when unset or blank."""
    env = os.environ if env is None else env
    return env.get(ENGINE_ENV, "").strip() or PYTHON


def selected(words: Sequence[str], env: Mapping[str, str] | None = None) -> str:
    """The engine that runs the command *words*: ``OPENTIDE_ENGINE`` as written, else its default.

    A default of ``rust`` counts only for a command that has a Rust
    implementation (:data:`RUST_COMMANDS`).
    """
    env = os.environ if env is None else env
    written = env.get(ENGINE_ENV, "").strip()
    if written:
        return written
    engine = default_engine(tuple(words))
    return engine if engine == PYTHON or tuple(words) in RUST_COMMANDS else PYTHON


def plugin_default(
    words: Sequence[str], args: Sequence[str], env: Mapping[str, str] | None = None
) -> bool:
    """Whether the default engine runs *args* on Rust: a run on an installed platform plugin.

    Only the Rust core has the plugin hook (UC-4.5, #835), so ``query``,
    ``validate query`` and ``deploy`` with a ``--platform`` every value of
    which names an installed plugin (:meth:`RustCommand.plugin_run`) run on
    Rust when ``OPENTIDE_ENGINE`` is unset or blank (UC-4.5b): the Python
    command line never parses a plugin's name. ``OPENTIDE_ENGINE`` set to any
    value keeps its meaning: under ``python`` the Python command line refuses
    the name, and ``compare`` refuses the run.
    """
    env = os.environ if env is None else env
    if env.get(ENGINE_ENV, "").strip():
        return False
    rust = RUST_COMMANDS.get(tuple(words))
    return rust is not None and rust.plugin_run(args) and rust.covers(args)


def rust_command(
    words: Sequence[str],
    env: Mapping[str, str] | None = None,
    args: Sequence[str] | None = None,
) -> RustCommand | None:
    """The Rust implementation that runs *words* now, or ``None`` when Python does (or must refuse).

    For hosts that run commands in their own process (``serve``): ``rust``
    selected (or, under the default engine, a platform plugin's run:
    :func:`plugin_default`) and a Rust implementation that covers *args*, the
    run's command line (:meth:`RustCommand.covers`). ``compare``, an unknown engine and
    ``rust`` for a command, or a run of it, without one go through
    :func:`dispatch`, which refuses as at a terminal.
    """
    if selected(words, env) != RUST and not (args is not None and plugin_default(words, args, env)):
        return None
    rust = RUST_COMMANDS.get(tuple(words))
    if rust is None or (args is not None and not rust.covers(args)):
        return None
    return rust


def dispatch(cli_ctx: CliContext, click_ctx: _click.Context) -> None:
    """Run the command as ``OPENTIDE_ENGINE`` says: return to run Python, or exit.

    Called by the root callback once the context is set up and ``--repo``
    checked, before the command's own options are parsed.
    """
    from opentide.cli.lazy import ROOT_ARGS_KEY, command_words
    from opentide.cli.ui.contract import (
        ENGINE_NOT_PORTED,
        USAGE_EXIT_CODE,
        USAGE_INVALID_CHOICE,
        did_you_mean,
    )

    if click_ctx.resilient_parsing or (requested() == PYTHON and os.environ.get(ENGINE_ENV)):
        # OPENTIDE_ENGINE=python: Python, whatever the command's default.
        return
    args = list(click_ctx.meta.get(ROOT_ARGS_KEY, ()))
    if "--help" in (args[: args.index("--")] if "--" in args else args):
        # Help is the command tree's, printed by Click, not an implementation's.
        return
    words = command_words(click_ctx.command, args)
    engine = selected(words)
    if engine == COMPARE and words in UNCOMPARED_RUST:
        # A full-screen UI cannot run twice to be compared: the Rust one opens.
        engine = RUST
    if engine == PYTHON:
        if not plugin_default(words, args):
            return
        # A platform plugin's run: only the Rust core reaches the plugin.
        engine = RUST
    path = " ".join(words) or "(no command)"
    if engine not in ENGINES:
        _fail(
            cli_ctx,
            path,
            f"{ENGINE_ENV}={engine} is not an engine. Choose {', '.join(ENGINES)}.",
            code=USAGE_INVALID_CHOICE,
            exit_code=USAGE_EXIT_CODE,
            argument=ENGINE_ENV,
            suggestion=did_you_mean(engine, ENGINES),
        )
    if words in ENGINE_HOSTS and not (engine == RUST and words in RUST_COMMANDS):
        # The host runs; what it runs reads the engine.
        return
    rust = RUST_COMMANDS.get(words)
    if rust is not None and not rust.covers(args):
        path = rust.uncovered(path, args)
        rust = None
    if rust is None:
        if engine == RUST:
            _fail(
                cli_ctx,
                " ".join(words) or "(no command)",
                f"opentide {path} has no Rust implementation yet: "
                f"unset {ENGINE_ENV}, or set it to {PYTHON} or {COMPARE}.",
                code=ENGINE_NOT_PORTED,
                exit_code=USAGE_EXIT_CODE,
                argument=ENGINE_ENV,
            )
        # compare: there is nothing to compare with yet, so Python runs alone,
        # and what it calls in this process (run_validation) runs Python too.
        from opentide.core.logging import get_logger

        get_logger(__name__).debug("engine_compare_python_only", command=path)
        os.environ[ENGINE_ENV] = PYTHON
        return
    if engine == RUST:
        if rust.launch == RUST_CLI:
            from opentide.analysis import EngineUnavailableError, engine

            try:
                engine()
            except EngineUnavailableError as exc:
                # The command line is compiled into the engine, which does not load.
                _fail(cli_ctx, path, str(exc), code=exc.code, exit_code=1)
        raise SystemExit(_run_rust(rust, args))
    _compare(cli_ctx, path, args, rust)


def _run_rust(rust: RustCommand, args: Sequence[str]) -> int:
    """Run the Rust implementation in this terminal; its exit code, a signal as 128 + n.

    The Rust command line compiled into this package (:data:`RUST_CLI`) runs
    in this process, as the console script runs it (:mod:`opentide.cli.launch`),
    with the environment this one started with: Ctrl-C and signals reach the
    command itself. Another launch (a stand-in a test registers), or streams
    that live in memory, run as a child: Ctrl-C reaches the child, which
    reports it, and this process waits for it instead of printing a second
    report.
    """
    import signal
    import subprocess

    # A stream this process replaced in memory (an embedding host's capture,
    # Click's test runner) has no file descriptor for the child to inherit:
    # the child's bytes are passed through it, or they would bypass it.
    own_out, own_err, own_in = (_descriptor(s) for s in (sys.stdout, sys.stderr, sys.stdin))
    if rust.launch == RUST_CLI and None not in (own_out, own_err, own_in):
        from opentide.cli.rust import run_in_process

        return run_in_process(args, _environment(RUST))
    try:
        # A handler that does nothing, not SIG_IGN: an ignored signal stays
        # ignored across exec, and the child could not be interrupted at all.
        previous = signal.signal(signal.SIGINT, lambda *_: None)
    except ValueError:  # not the main thread: nothing to hand Ctrl-C over
        previous = None
    given = None if own_in is not None else _read_all(sys.stdin)
    try:
        child = subprocess.run(
            [*rust.launch, *args],
            env=_environment(RUST),
            check=False,
            stdout=None if own_out is not None else subprocess.PIPE,
            stderr=None if own_err is not None else subprocess.PIPE,
            input=given,
        )
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)
    for captured, stream in ((child.stdout, sys.stdout), (child.stderr, sys.stderr)):
        if captured:
            _write_through(stream, captured)
    return 128 - child.returncode if child.returncode < 0 else child.returncode


def _descriptor(stream: Any) -> int | None:
    """*stream*'s file descriptor, or ``None`` when it lives in memory."""
    try:
        return int(stream.fileno())
    except (AttributeError, OSError, ValueError):
        return None


def _read_all(stream: Any) -> bytes:
    """What an in-memory stdin holds, for the child: nothing when it holds nothing readable."""
    try:
        data = stream.buffer.read() if hasattr(stream, "buffer") else stream.read()
    except (AttributeError, OSError, ValueError):
        return b""
    return data.encode("utf-8") if isinstance(data, str) else bytes(data or b"")


def _write_through(stream: Any, data: bytes) -> None:
    """*data* written to *stream* as bytes when it takes them, else as UTF-8 text."""
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        stream.flush()
        buffer.write(data)
        buffer.flush()
    else:
        stream.write(data.decode("utf-8", errors="replace"))
    stream.flush()


def _fail(
    cli_ctx: CliContext,
    path: str,
    message: str,
    *,
    code: str,
    exit_code: int,
    argument: str | None = None,
    suggestion: str | None = None,
) -> NoReturn:
    """Fail the run of *path* with *code*: the envelope names the command it was for."""
    from opentide.cli.output import CommandResult, emit_result
    from opentide.cli.ui.contract import Failure

    emit_result(
        cli_ctx,
        CommandResult(
            message=message,
            ok=False,
            status="failed",
            data={"error": message},
            exit_code=exit_code,
            failure=Failure(code=code, message=message, argument=argument, suggestion=suggestion),
            command=path,
        ),
    )
    raise AssertionError("a failed result did not exit")


def _environment(engine: str, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment a child runs in: the CLI's own at launch, with *engine* chosen."""
    from opentide.cli import launch_environment

    env = dict(launch_environment() if base is None else base)
    env[ENGINE_ENV] = engine
    return env


class _Copy:
    """One implementation's copy of the workspace."""

    __slots__ = ("original", "root")

    def __init__(self, original: Path, root: Path) -> None:
        self.original = original
        self.root = root

    def map_path(self, value: str) -> str:
        """*value* inside the copy when it is an absolute path inside the workspace."""
        from pathlib import Path

        if not value or not os.path.isabs(value):
            return value
        try:
            relative = Path(value).resolve().relative_to(self.original)
        except (ValueError, OSError):
            return value
        return str(self.root / relative)

    def map_argument(self, token: str) -> str:
        """An argument, or the value of ``--option=value``, mapped into the copy."""
        name, separator, value = token.partition("=")
        if separator and name.startswith("-"):
            return f"{name}={self.map_path(value)}"
        return self.map_path(token)


def _map_args(args: Sequence[str], copy: _Copy) -> list[str]:
    """*args* for a run in *copy*: absolute paths and ``--repo``'s value point into it.

    Relative paths resolve against the working directory, which the run takes
    inside the copy when it is inside the workspace.
    """
    from pathlib import Path

    mapped: list[str] = []
    tokens = iter(args)
    for token in tokens:
        if token == "--":
            mapped.append(token)
            mapped.extend(copy.map_argument(rest) for rest in tokens)
            break
        if token == "--repo":
            value = next(tokens, None)
            mapped.append(token)
            if value is not None:
                mapped.append(copy.map_path(str(Path(value).resolve())))
            continue
        if token.startswith("--repo="):
            value = token.partition("=")[2]
            mapped.append(f"--repo={copy.map_path(str(Path(value).resolve()))}")
            continue
        mapped.append(copy.map_argument(token))
    return mapped


#: A file as a snapshot records it: its permission bits, size and modification time.
_Stamp = tuple[int, int, int]


def _walk(root: Path) -> Iterator[tuple[str, Path, os.stat_result]]:
    """Every file under *root* (symbolic links as themselves), with its relative path."""
    from pathlib import Path

    for folder, folders, files in os.walk(root, followlinks=False):
        folders.sort()
        base = Path(folder)
        for name in sorted(files) + [name for name in folders if (base / name).is_symlink()]:
            path = base / name
            try:
                info = path.lstat()
            except OSError:
                continue
            yield path.relative_to(root).as_posix(), path, info


def _snapshot(root: Path) -> dict[str, _Stamp]:
    return {name: (_mode(info), info.st_size, info.st_mtime_ns) for name, _, info in _walk(root)}


#: What a symbolic link's contents start with; its mode carries ``S_IFLNK`` too.
_LINK_PREFIX = b"symlink:"


def _contents(path: Path) -> bytes:
    """A file's bytes, or a symbolic link's target."""
    if path.is_symlink():
        return _LINK_PREFIX + os.fsencode(os.readlink(path))
    return path.read_bytes()


def _mode(info: os.stat_result) -> int:
    """The permission bits, with ``S_IFLNK`` for a link: a file never equals a link."""
    bits = stat.S_IMODE(info.st_mode)
    return bits | stat.S_IFLNK if stat.S_ISLNK(info.st_mode) else bits


def _changes(
    copy: _Copy, before: Mapping[str, _Stamp]
) -> list[tuple[str, int | None, bytes | None]]:
    """The files the run created, changed (bytes or mode) or deleted in *copy*.

    A file whose stamp changed is compared with the workspace it was copied
    from, so rewriting a file with the same bytes is no change.
    """
    changes: list[tuple[str, int | None, bytes | None]] = []
    seen: set[str] = set()
    for name, path, info in _walk(copy.root):
        seen.add(name)
        mode = _mode(info)
        if before.get(name) == (mode, info.st_size, info.st_mtime_ns):
            continue
        data = _contents(path)
        original = copy.original / name
        if name in before:
            try:
                same = _contents(original) == data
                same = same and _mode(original.lstat()) == mode
            except OSError:
                same = False
            if same:
                continue
        changes.append((name, mode, data))
    changes.extend((name, None, None) for name in before if name not in seen)
    return sorted(changes, key=lambda change: change[0])


def _path_forms(path: Path) -> list[str]:
    """How *path* can appear in output: as it is, resolved, and escaped in JSON."""
    import json

    forms: list[str] = []
    for text in dict.fromkeys((str(path), str(path.resolve()))):
        for form in (text, json.dumps(text)[1:-1], json.dumps(text, ensure_ascii=False)[1:-1]):
            if form not in forms:
                forms.append(form)
    return forms


def _special(folder: str, names: list[str]) -> list[str]:
    """``copytree``'s ignore: sockets, pipes and devices, which cannot be copied."""
    skipped = []
    for name in names:
        try:
            mode = os.lstat(os.path.join(folder, name)).st_mode
        except OSError:
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            skipped.append(name)
    return skipped


def _copy_workspace(workspace: Path, root: Path) -> _Copy:
    """Copy *workspace* to *root*; absolute links into it point into the copy instead."""
    import shutil

    root.parent.mkdir(parents=True)
    shutil.copytree(workspace, root, symlinks=True, ignore=_special)
    copy = _Copy(original=workspace, root=root)
    for _, path, info in list(_walk(root)):
        if not stat.S_ISLNK(info.st_mode):
            continue
        target = os.readlink(path)
        mapped = copy.map_path(target)
        if mapped != target:
            path.unlink()
            path.symlink_to(mapped)
    return copy


class _Side:
    """What one implementation did, and the copy it did it in."""

    __slots__ = ("copy", "run")

    def __init__(self, run: CompareRun, copy: _Copy) -> None:
        self.run = run
        self.copy = copy


def _run_side(
    engine: str,
    launch: Sequence[str],
    args: Sequence[str],
    workspace: Path,
    scratch: Path,
    extra_env: Mapping[str, str] | None = None,
) -> _Side:
    """Run one implementation on its own copy of *workspace*; what it did, for the comparator.

    *extra_env* is added to its environment as is (no path in it is mapped).
    """
    import subprocess
    from datetime import datetime, timedelta, timezone
    from pathlib import Path

    from opentide.cli.ui.mode import OUTPUT_ENV_VALUES, get_mode, json_indent

    copy = _copy_workspace(workspace, scratch / engine / workspace.name)
    env = {name: copy.map_path(value) for name, value in _environment(engine).items()}
    env.update(extra_env or {})
    # Both runs print as this one would: the mode and the JSON layout it
    # resolved, although their stdout is a pipe.
    mode = get_mode().value
    if mode in OUTPUT_ENV_VALUES:
        env["OPENTIDE_OUTPUT"] = mode
    env["OPENTIDE_JSON_INDENT"] = "2" if json_indent() else "0"
    run_in = Path(copy.map_path(str(Path.cwd().resolve())))
    before = _snapshot(copy.root)
    started = datetime.now(timezone.utc)
    child = subprocess.run(
        [*launch, *_map_args(args, copy)],
        cwd=run_in,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    finished = datetime.now(timezone.utc)
    literals = [(form, WORKSPACE_PLACEHOLDER) for form in _path_forms(copy.root)]
    dates = sorted({f"{started:%Y-%m-%d}", f"{finished:%Y-%m-%d}"})
    # As the goldens: date-times of the week before the run are the clock too
    # (``query`` starts its default window 24 hours ago).
    recent = [f"{started - timedelta(days=days):%Y-%m-%d}" for days in range(1, 8)]
    run = (
        child.returncode,
        child.stdout,
        child.stderr,
        _changes(copy, before),
        literals,
        dates,
        recent,
    )
    return _Side(run=run, copy=copy)


def _outside(args: Sequence[str], workspace: Path) -> str | None:
    """The first path in *args* outside *workspace*, which no copy isolates.

    An absolute path, or a relative one that climbs with ``..``: the run's
    working directory is inside the workspace, so only those can leave it.
    """
    from pathlib import Path

    for token in args:
        name, separator, value = token.partition("=")
        candidate = value if separator and name.startswith("-") else token
        if not candidate:
            continue
        relative = not os.path.isabs(candidate)
        if relative and ".." not in Path(candidate).parts:
            continue
        try:
            if not Path(candidate).resolve().is_relative_to(workspace):
                return candidate
        except OSError:
            return candidate
    return None


def _compare(cli_ctx: CliContext, path: str, args: Sequence[str], rust: RustCommand) -> NoReturn:
    """Run both implementations and compare them: Python's result as its own, or fail with 70.

    Both run on copies, so neither touches the workspace. When they agree, the
    Python run's output is printed with the copy's path read as the
    workspace's, and the files it changed are changed in the workspace.
    """
    import json
    import shutil
    import tempfile
    from pathlib import Path

    from opentide.analysis import EngineUnavailableError, compare_runs
    from opentide.cli.ui.contract import (
        COMMAND_FAILED,
        ENGINE_MISMATCH,
        ENGINE_MISMATCH_EXIT_CODE,
        USAGE_ERROR,
        USAGE_EXIT_CODE,
    )

    options = list(args[: args.index("--")] if "--" in args else args)
    sends = rust.side_effects and not any(flag in options for flag in rust.offline)
    if sends or rust.plugin_run(args):
        # A plugin's deploy or query reaches its tenant: so would both runs.
        _fail(
            cli_ctx,
            path,
            f"{ENGINE_ENV}={COMPARE} cannot compare opentide {path}: it reaches outside the "
            f"workspace (a tenant or a sharing destination), and both runs would. "
            f"Use {PYTHON} or {RUST}.",
            code=USAGE_ERROR,
            exit_code=USAGE_EXIT_CODE,
            argument=ENGINE_ENV,
        )
    workspace = cli_ctx.repo.resolve()
    outside = (
        str(Path.cwd()) if not Path.cwd().resolve().is_relative_to(workspace) else None
    ) or _outside(args, workspace)
    if outside is not None:
        # Each implementation runs on its own copy of the workspace; a path
        # outside it would be read and written by both, unseen by the comparison.
        _fail(
            cli_ctx,
            path,
            f"{ENGINE_ENV}={COMPARE} compares runs inside the workspace, {workspace}, "
            f"and {outside} is outside it: run from inside it, with paths inside it.",
            code=USAGE_ERROR,
            exit_code=USAGE_EXIT_CODE,
            argument=ENGINE_ENV,
        )
    with tempfile.TemporaryDirectory(prefix="opentide-compare-") as scratch:
        refusal = Path(scratch) / "rust-refusal"
        try:
            oracle = _run_side(PYTHON, python_launch(), args, workspace, Path(scratch))
            candidate = _run_side(
                RUST,
                rust.launch,
                args,
                workspace,
                Path(scratch),
                extra_env={REFUSAL_ENV: str(refusal)},
            )
        except (OSError, shutil.Error) as exc:
            _fail(
                cli_ctx,
                path,
                f"{ENGINE_ENV}={COMPARE} could not copy the workspace or run a side: {exc}",
                code=COMMAND_FAILED,
                exit_code=1,
            )
        if refusal.exists():
            # The Rust implementation does not cover this input: nothing to
            # compare with, so the Python run is the result.
            from opentide.core.logging import get_logger

            get_logger(__name__).debug(
                "engine_compare_python_only",
                command=path,
                reason=refusal.read_text(encoding="utf-8", errors="replace"),
            )
            _adopt(cli_ctx, path, oracle, workspace, agreed=False)
        try:
            report: dict[str, Any] = json.loads(
                compare_runs(
                    path,
                    oracle.run,
                    candidate.run,
                    rules=rust.rules,
                    known=_known_texts(workspace) if "fresh-uuids" in rust.rules else (),
                    git_version=_git_version() if "host-git" in rust.rules else None,
                )
            )
        except EngineUnavailableError as exc:
            _fail(cli_ctx, path, str(exc), code=exc.code, exit_code=1)
        except UnicodeError as exc:
            _fail(cli_ctx, path, f"{ENGINE_ENV}={COMPARE}: {exc}", code=COMMAND_FAILED, exit_code=1)
        if report.get("equal"):
            _adopt(cli_ctx, path, oracle, workspace, agreed=True)
    written = _write_report(cli_ctx, path, args, report)
    count = len(report.get("differences", [])) + int(report.get("omitted", 0))
    message = (
        f"The Python and Rust implementations of opentide {path} differ "
        f"({count} difference{'' if count == 1 else 's'}); the report is {written}"
    )
    _fail(cli_ctx, path, message, code=ENGINE_MISMATCH, exit_code=ENGINE_MISMATCH_EXIT_CODE)


def _adopt(
    cli_ctx: CliContext, path: str, oracle: _Side, workspace: Path, *, agreed: bool
) -> NoReturn:
    """Make the Python run the result: its changes made in *workspace*, its output, its exit.

    *agreed*: both implementations ran and agreed, rather than Python alone.
    """
    from opentide.cli.ui.contract import COMMAND_FAILED

    back = _back_to(oracle.copy, workspace)
    try:
        _apply(oracle.run[3], workspace, back)
    except OSError as exc:
        _fail(
            cli_ctx,
            path,
            f"{ENGINE_ENV}={COMPARE}: {'both agreed, but ' if agreed else ''}the workspace "
            f"could not take the changes: {exc}",
            code=COMMAND_FAILED,
            exit_code=1,
        )
    _replay(back(oracle.run[1]), back(oracle.run[2]))
    code = oracle.run[0]
    raise SystemExit(128 - code if code < 0 else code)


def _known_texts(workspace: Path) -> list[str]:
    """The UTF-8 texts of the workspace before the run: the UUIDs in them are not fresh."""
    texts: list[str] = []
    for _, path, info in _walk(workspace):
        if not stat.S_ISREG(info.st_mode) or ".git" in path.relative_to(workspace).parts:
            continue
        try:
            texts.append(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
    return texts


def _git_version() -> str | None:
    """``git --version``'s number, as the goldens normalise it for ``host-git``."""
    import subprocess

    try:
        out = subprocess.run(
            ["git", "--version"], capture_output=True, text=True, check=False, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    words = out.split()
    return words[2] if len(words) >= 3 else None


def _back_to(copy: _Copy, workspace: Path) -> Callable[[bytes], bytes]:
    """Bytes with the copy's path, in each form, read as the workspace's in the same form."""
    import json

    texts = dict.fromkeys((str(copy.root), str(copy.root.resolve())))
    pairs: list[tuple[str, str]] = []
    for text in texts:
        for encode in (
            lambda value: value,
            lambda value: json.dumps(value)[1:-1],
            lambda value: json.dumps(value, ensure_ascii=False)[1:-1],
        ):
            pairs.append((encode(text), encode(str(workspace))))
    pairs = sorted(dict(pairs).items(), key=lambda pair: len(pair[0]), reverse=True)

    def back(data: bytes) -> bytes:
        for copied, real in pairs:
            data = data.replace(os.fsencode(copied), os.fsencode(real))
        return data

    return back


def _apply(
    changes: Sequence[tuple[str, int | None, bytes | None]],
    workspace: Path,
    back: Callable[[bytes], bytes],
) -> None:
    """Make in *workspace* the changes the agreed run made in its copy."""
    for name, mode, data in changes:
        target = workspace / name
        if mode is None or data is None:
            if target.is_symlink() or target.is_file():
                target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            target.unlink()
        if stat.S_ISLNK(mode):
            target.unlink(missing_ok=True)
            target.symlink_to(os.fsdecode(back(data.removeprefix(_LINK_PREFIX))))
            continue
        target.write_bytes(back(data))
        target.chmod(stat.S_IMODE(mode))


def _replay(stdout: bytes, stderr: bytes) -> None:
    """Write the agreed run's output as it printed it, byte for byte."""
    for stream, data in ((sys.stdout, stdout), (sys.stderr, stderr)):
        if stream is None or not data:
            continue
        stream.flush()
        buffer = getattr(stream, "buffer", None)
        if buffer is not None:
            buffer.write(data)
            buffer.flush()
        else:
            stream.write(data.decode("utf-8", errors="replace"))
            stream.flush()


def report_dir(env: Mapping[str, str] | None = None) -> Path:
    """Where diff reports go: ``compare/`` in the state directory crash logs use.

    ``$XDG_STATE_HOME/opentide/compare`` (``~/.local/state/opentide/compare``)
    on Linux and other Unix systems.
    """
    from opentide.cli.ui.crash import crash_log_dir

    return crash_log_dir(env=env) / "compare"


def _write_report(
    cli_ctx: CliContext, path: str, args: Sequence[str], report: Mapping[str, Any]
) -> str:
    """Write the diff report, redacted; its path, or why it could not be written."""
    import json
    from datetime import datetime, timezone

    from opentide.cli.ui.crash import workspace_redactor

    redact = workspace_redactor([cli_ctx.repo])

    def scrub(value: Any) -> Any:
        if isinstance(value, str):
            return redact(value)
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()}
        return value

    now = datetime.now(timezone.utc)
    document = {
        "schema_version": 1,
        "command": path,
        "argv": redact.argv(args),
        "created": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "oracle": PYTHON,
        "candidate": RUST,
        **{key: scrub(value) for key, value in report.items() if key not in ("command", "case")},
    }
    try:
        directory = report_dir()
        for folder in (directory.parent, directory):
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            folder.chmod(0o700)
        stamp = f"{now:%Y%m%dT%H%M%S%f}Z"
        for attempt in range(100):
            target = directory / (f"{stamp}.json" if attempt == 0 else f"{stamp}-{attempt}.json")
            try:
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
            return str(target)
    except (OSError, RuntimeError) as exc:
        return f"not written ({exc})"
    return "not written (no free name)"
