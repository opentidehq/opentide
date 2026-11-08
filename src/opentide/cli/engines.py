"""``OPENTIDE_ENGINE``: which implementation of a command runs (plan §5.2, #805).

During the move to one Rust core, a command can have two implementations:
the Python one, which every command has and which is the oracle, and a Rust
one. ``OPENTIDE_ENGINE`` chooses, read once per process by the root callback:

- ``python`` (the default, also when unset or empty): the Python implementation.
- ``rust``: the Rust implementation. A command without one is a usage error,
  ``failure.code`` ``engine_unavailable``, exit 2.
- ``compare``: both, each on its own copy of the workspace, and their exit
  codes, stdout, stderr and the files they wrote are compared with the
  comparator ``cargo xtask compare`` uses (``crates/opentide-compare``). If they
  agree, the Python run's output and exit code are the result; if not, exit 70,
  ``failure.code`` ``engine_mismatch``, and a diff report in the state
  directory whose path the message names. A command without a Rust
  implementation runs Python alone.

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
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from typer import _click

    from opentide.analysis import CompareRun
    from opentide.cli.context import CliContext

#: The variable that chooses the implementation.
ENGINE_ENV = "OPENTIDE_ENGINE"
PYTHON = "python"
RUST = "rust"
COMPARE = "compare"
#: The values ``OPENTIDE_ENGINE`` accepts.
ENGINES = (PYTHON, RUST, COMPARE)

#: What the workspace copy's path reads as in both runs before they are compared.
WORKSPACE_PLACEHOLDER = "<WS>"


@dataclass(frozen=True)
class RustCommand:
    """A command's Rust implementation: the command line that runs it.

    The command's arguments follow *launch*. It runs with ``OPENTIDE_ENGINE``
    set to ``rust`` in its environment.
    """

    launch: tuple[str, ...]


#: Command paths (``("validate",)``, ``("generate", "docs")``) that have a Rust
#: implementation. Every command has its Python one. Empty until a command is
#: ported (UC-2.7, UC-3.x); a path is added here in the change that ports it.
RUST_COMMANDS: dict[tuple[str, ...], RustCommand] = {}


def python_launch() -> tuple[str, ...]:
    """The command line that runs this installation's Python CLI."""
    return (sys.executable, "-m", "opentide")


def requested(env: Mapping[str, str] | None = None) -> str:
    """The engine ``OPENTIDE_ENGINE`` names, as written; ``python`` when unset or blank."""
    env = os.environ if env is None else env
    return env.get(ENGINE_ENV, "").strip() or PYTHON


def dispatch(cli_ctx: CliContext, click_ctx: _click.Context) -> None:
    """Run the command as ``OPENTIDE_ENGINE`` says: return to run Python, or exit.

    Called by the root callback once the context is set up and ``--repo``
    checked, before the command's own options are parsed.
    """
    from opentide.analysis import ENGINE_UNAVAILABLE
    from opentide.cli.lazy import ROOT_ARGS_KEY, command_words
    from opentide.cli.ui.contract import USAGE_EXIT_CODE, USAGE_INVALID_CHOICE, did_you_mean

    engine = requested()
    if engine == PYTHON:
        return
    args = list(click_ctx.meta.get(ROOT_ARGS_KEY, ()))
    words = command_words(click_ctx.command, args)
    path = " ".join(words)
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
    rust = RUST_COMMANDS.get(words)
    if rust is None:
        if engine == RUST:
            _fail(
                cli_ctx,
                path,
                f"opentide {path} has no Rust implementation yet: "
                f"unset {ENGINE_ENV}, or set it to {PYTHON} or {COMPARE}.",
                code=ENGINE_UNAVAILABLE,
                exit_code=USAGE_EXIT_CODE,
                argument=ENGINE_ENV,
            )
        # compare: there is nothing to compare with yet, so Python runs alone.
        from opentide.core.logging import get_logger

        get_logger(__name__).debug("engine_compare_python_only", command=path)
        return
    if engine == RUST:
        child = subprocess.run([*rust.launch, *args], env=_environment(RUST), check=False)
        raise SystemExit(child.returncode)
    _compare(cli_ctx, path, args, rust)


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
    return {
        name: (stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns)
        for name, _, info in _walk(root)
    }


def _contents(path: Path) -> bytes:
    """A file's bytes, or a symbolic link's target."""
    if path.is_symlink():
        return b"symlink:" + os.fsencode(os.readlink(path))
    return path.read_bytes()


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
        mode = stat.S_IMODE(info.st_mode)
        if before.get(name) == (mode, info.st_size, info.st_mtime_ns):
            continue
        data = _contents(path)
        original = copy.original / name
        if name in before:
            try:
                same = _contents(original) == data
                same = same and stat.S_IMODE(original.lstat().st_mode) == mode
            except OSError:
                same = False
            if same:
                continue
        changes.append((name, mode, data))
    changes.extend((name, None, None) for name in before if name not in seen)
    return sorted(changes, key=lambda change: change[0])


def _run_side(
    engine: str, launch: Sequence[str], args: Sequence[str], workspace: Path, scratch: Path
) -> CompareRun:
    """Run one implementation on its own copy of *workspace*; what it did, for the comparator."""
    from opentide.cli.ui.mode import OUTPUT_ENV_VALUES, get_mode, json_indent

    root = scratch / engine / workspace.name
    root.parent.mkdir(parents=True)
    shutil.copytree(workspace, root, symlinks=True)
    copy = _Copy(original=workspace, root=root)
    env = {name: copy.map_path(value) for name, value in _environment(engine).items()}
    # Both runs print as this one would: the mode and the JSON layout it
    # resolved, although their stdout is a pipe.
    mode = get_mode().value
    if mode in OUTPUT_ENV_VALUES:
        env["OPENTIDE_OUTPUT"] = mode
    env["OPENTIDE_JSON_INDENT"] = "2" if json_indent() else "0"
    cwd = Path.cwd().resolve()
    run_in = Path(copy.map_path(str(cwd)))
    before = _snapshot(root)
    child = subprocess.run(
        [*launch, *_map_args(args, copy)],
        cwd=run_in,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    replacements = [(os.fsencode(str(root)), WORKSPACE_PLACEHOLDER.encode())]
    resolved = root.resolve()
    if resolved != root:
        replacements.append((os.fsencode(str(resolved)), WORKSPACE_PLACEHOLDER.encode()))
    return (child.returncode, child.stdout, child.stderr, _changes(copy, before), replacements)


def _compare(cli_ctx: CliContext, path: str, args: Sequence[str], rust: RustCommand) -> NoReturn:
    """Run both implementations and compare them: replay Python's result, or fail with 70."""
    import json

    from opentide.analysis import EngineUnavailableError, compare_runs
    from opentide.cli.ui.contract import ENGINE_MISMATCH, ENGINE_MISMATCH_EXIT_CODE

    workspace = cli_ctx.repo.resolve()
    with tempfile.TemporaryDirectory(prefix="opentide-compare-") as scratch:
        oracle = _run_side(PYTHON, python_launch(), args, workspace, Path(scratch))
        candidate = _run_side(RUST, rust.launch, args, workspace, Path(scratch))
    try:
        report: dict[str, Any] = json.loads(compare_runs(path, oracle, candidate))
    except EngineUnavailableError as exc:
        _fail(cli_ctx, path, str(exc), code=exc.code, exit_code=1)
    if report.get("equal"):
        _replay(oracle[1], oracle[2])
        raise SystemExit(oracle[0])
    written = _write_report(cli_ctx, path, args, report)
    count = len(report.get("differences", [])) + int(report.get("omitted", 0))
    message = (
        f"The Python and Rust implementations of opentide {path} differ "
        f"({count} difference{'' if count == 1 else 's'}); the report is {written}"
    )
    _fail(cli_ctx, path, message, code=ENGINE_MISMATCH, exit_code=ENGINE_MISMATCH_EXIT_CODE)


def _replay(stdout: bytes, stderr: bytes) -> None:
    """Write the oracle's output as it printed it, byte for byte."""
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
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
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
