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
  some inputs only, such as ``generate docs`` on threats whose CVE details
  only Python fetches.

:data:`RUST_COMMANDS` is the dispatch table: the work items that port a
command add it there.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from typer import _click

    from opentide.analysis import CompareRun
    from opentide.cli.context import CliContext

from opentide.cli.engine_defaults import ENGINE_ENV, PYTHON, RUST, default_engine

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


@dataclass(frozen=True)
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

    *requires* names flags of which a run must carry one for the Rust
    implementation to cover it (``deploy`` runs in Rust with ``--dry-run``
    only); a run without any is a command with no Rust implementation:
    ``rust`` refuses it with ``engine_not_ported`` and ``compare`` runs
    Python alone. *refuses* names flags a run must carry none of: ``validate
    query --live`` checks the queries on the tenants, which stays Python's
    until UC-4.1, so a run with it is one with no Rust implementation.
    """

    launch: tuple[str, ...]
    rules: tuple[str, ...] = ()
    side_effects: bool = False
    requires: tuple[str, ...] = ()
    refuses: tuple[str, ...] = ()

    def covers(self, args: Sequence[str]) -> bool:
        """Whether the Rust implementation runs the command with *args*."""
        options = args[: args.index("--")] if "--" in args else args
        if any(flag in options for flag in self.refuses):
            return False
        return not self.requires or any(flag in options for flag in self.requires)

    def uncovered(self, path: str, args: Sequence[str]) -> str:
        """*path* as a run of *args* it does not cover reads: ``deploy without --dry-run``."""
        options = args[: args.index("--")] if "--" in args else args
        refused = [flag for flag in self.refuses if flag in options]
        if refused:
            return f"{path} with {' and '.join(refused)}"
        return f"{path} without {' or '.join(self.requires)}"


#: Commands that host others and apply ``OPENTIDE_ENGINE`` to what they run
#: rather than to themselves: ``serve`` runs each request on the engine its
#: command selects (#822), and the MCP server's read tools do the same. They
#: run under any engine; one that is also in :data:`RUST_COMMANDS` runs its
#: Rust implementation under ``rust`` (``mcp start``, UC-3.7, #829), and its
#: Python one, the host, under ``compare``: an MCP call under ``compare``
#: answers with Python's result and records a Rust difference (#822). ``lsp
#: start`` (UC-3.6b, #947) is one too: an editor's session has one server on
#: stdio, so ``compare`` runs the Python host and ``rust`` the Rust one.
ENGINE_HOSTS: frozenset[tuple[str, ...]] = frozenset(
    {("serve",), ("mcp", "start"), ("lsp", "start")}
)

#: The Rust command line compiled into ``opentide._native`` (:mod:`opentide.cli.rust`).
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
#: (``opentide.mcp_server.bridge``); ``lsp start`` with UC-3.6b (#947): the
#: language server hosted by the Rust command line.
RUST_COMMANDS: dict[tuple[str, ...], RustCommand] = {
    ("commands",): RustCommand(launch=RUST_CLI),
    ("explain",): RustCommand(launch=RUST_CLI),
    ("info",): RustCommand(launch=RUST_CLI),
    ("lint",): RustCommand(launch=RUST_CLI),
    ("validate",): RustCommand(launch=RUST_CLI),
    ("validate", "query"): RustCommand(launch=RUST_CLI, refuses=("--live",)),
    ("rules", "unreviewed"): RustCommand(launch=RUST_CLI),
    ("deploy",): RustCommand(launch=RUST_CLI, requires=("--dry-run",)),
    ("doctor",): RustCommand(launch=RUST_CLI, rules=("host-git",), requires=("--offline",)),
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
    ("mcp", "start"): RustCommand(launch=RUST_CLI),
    ("lsp", "start"): RustCommand(launch=RUST_CLI),
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


def rust_command(
    words: Sequence[str],
    env: Mapping[str, str] | None = None,
    args: Sequence[str] | None = None,
) -> RustCommand | None:
    """The Rust implementation that runs *words* now, or ``None`` when Python does (or must refuse).

    For hosts that run commands in their own process (``serve``): ``rust``
    selected and a Rust implementation that covers *args*, the run's command
    line (:meth:`RustCommand.covers`). ``compare``, an unknown engine and
    ``rust`` for a command, or a run of it, without one go through
    :func:`dispatch`, which refuses as at a terminal.
    """
    if selected(words, env) != RUST:
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
    if engine == PYTHON:
        return
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
        raise SystemExit(_run_rust(rust, args))
    _compare(cli_ctx, path, args, rust)


def _run_rust(rust: RustCommand, args: Sequence[str]) -> int:
    """Run the Rust implementation in this terminal; its exit code, a signal as 128 + n.

    Ctrl-C reaches the child, which reports it; this process waits for it
    instead of printing a second report.
    """
    import signal

    try:
        # A handler that does nothing, not SIG_IGN: an ignored signal stays
        # ignored across exec, and the child could not be interrupted at all.
        previous = signal.signal(signal.SIGINT, lambda *_: None)
    except ValueError:  # not the main thread: nothing to hand Ctrl-C over
        previous = None
    # A stream this process replaced in memory (an embedding host's capture,
    # Click's test runner) has no file descriptor for the child to inherit:
    # the child's bytes are passed through it, or they would bypass it.
    own_out, own_err, own_in = (_descriptor(s) for s in (sys.stdout, sys.stderr, sys.stdin))
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


@dataclass(frozen=True)
class _Copy:
    """One implementation's copy of the workspace."""

    original: Path
    root: Path

    def map_path(self, value: str) -> str:
        """*value* inside the copy when it is an absolute path inside the workspace."""
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


@dataclass(frozen=True)
class _Side:
    """What one implementation did, and the copy it did it in."""

    run: CompareRun
    copy: _Copy


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

    from opentide.analysis import EngineUnavailableError, compare_runs
    from opentide.cli.ui.contract import (
        COMMAND_FAILED,
        ENGINE_MISMATCH,
        ENGINE_MISMATCH_EXIT_CODE,
        USAGE_ERROR,
        USAGE_EXIT_CODE,
    )

    if rust.side_effects:
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
