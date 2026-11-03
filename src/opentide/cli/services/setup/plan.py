"""``opentide setup --plan``: what setup would write, worked out without writing it.

The plan runs the very same setup steps ``--yes`` runs, in a copy of the
repository in a temporary directory, and compares that copy's files before
and after each step. So the plan cannot drift from what setup does: a file
is ``create`` when a step made it, ``merge`` when a step wrote over one that
was there, ``delete`` when a step removed one, and ``skip`` when a step
reported it left as it was. The copy is
deleted afterwards; the repository itself is only read.

What the copy holds:

- the Git work tree around the target (the target alone outside Git), less
  the folders no setup step reads (``node_modules``, virtual environments,
  caches) and anything that is not a file, a folder or a link. A link that
  points outside the tree is copied as what it points at, so no step writes
  through it (:func:`_copy_tree`);
- a small ``.git`` with the real repository's ``HEAD``, configuration, refs and
  hooks, and its object store as an alternate, so ``git`` answers in the copy
  as it does in the repository (branches, ``core.hooksPath``).

A step that would write outside the repository (a ``core.hooksPath`` shared
with other repositories) writes nothing there in a plan either: it warns, as
it does when it runs.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Generator, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

PlanAction = Literal["create", "merge", "skip", "delete"]

#: Folders the copy leaves out: nothing setup writes depends on them, and they can be large.
SKIPPED_DIRS = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cache",
        ".terraform",
        "target",
        "dist",
        "build",
    }
)
#: The most the copy holds before the plan refuses: a work tree this big is not
#: a detection repository, or one whose copy would fill the temporary folder.
MAX_COPY_FILES = 50_000
MAX_COPY_BYTES = 512 * 1024 * 1024


class PlanRefused(Exception):
    """``--plan`` will not copy this tree; the message says why and what to do."""
#: What of ``.git`` the copy keeps; objects are read from the real store as an alternate.
_GIT_FILES = ("HEAD", "config", "packed-refs", "description")
_GIT_DIRS = ("refs", "hooks", "info")
#: Git variables that would point ``git`` in the copy back at the real repository.
_GIT_VARIABLES = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)
#: Variables that name the workspace; in a plan they name its copy.
_WORKSPACE_VARIABLES = ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE")

#: A file's size and modification time: a step that wrote it changed one of them.
Stamp = tuple[int, int]


@dataclass(frozen=True)
class PlannedFile:
    """One file a step would write, remove, or leave as it is."""

    path: str
    action: PlanAction

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "action": self.action}


@dataclass
class PlannedStep:
    """One setup step: the files it would write, and its warnings."""

    step: str
    files: list[PlannedFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "step": self.step,
            "files": [item.to_dict() for item in self.files],
            "warnings": list(self.warnings),
        }


def _git_root(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _nearest_existing(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return path


def _git_dirs(top: Path) -> tuple[Path, Path] | None:
    """The real repository's git directory and common directory, for a ``.git`` dir or file."""
    dot_git = top / ".git"
    if dot_git.is_dir():
        git_dir = dot_git
    elif dot_git.is_file():
        line = dot_git.read_text(encoding="utf-8", errors="replace").strip()
        if not line.startswith("gitdir:"):
            return None
        git_dir = Path(line.removeprefix("gitdir:").strip())
        if not git_dir.is_absolute():
            git_dir = (top / git_dir).resolve()
    else:
        return None
    common = git_dir
    pointer = git_dir / "commondir"
    if pointer.is_file():
        named = Path(pointer.read_text(encoding="utf-8").strip())
        common = named if named.is_absolute() else (git_dir / named).resolve()
    return git_dir, common


def _copy_git(top: Path, shadow_top: Path) -> None:
    """A ``.git`` in the copy that ``git`` reads as the real one, sharing its objects."""
    found = _git_dirs(top)
    if found is None:
        return
    git_dir, common = found
    target = shadow_top / ".git"
    target.mkdir(parents=True, exist_ok=True)
    head = git_dir / "HEAD"
    if head.is_file():
        shutil.copy2(head, target / "HEAD")
    for name in _GIT_FILES[1:]:
        source = common / name
        if source.is_file():
            shutil.copy2(source, target / name)
    for name in _GIT_DIRS:
        source = common / name
        if source.is_dir():
            shutil.copytree(source, target / name, symlinks=True, dirs_exist_ok=True)
    objects = target / "objects"
    (objects / "info").mkdir(parents=True, exist_ok=True)
    (objects / "pack").mkdir(exist_ok=True)
    real_objects = common / "objects"
    if real_objects.is_dir():
        (objects / "info" / "alternates").write_text(f"{real_objects}\n", encoding="utf-8")


def _copy_tree(top: Path, shadow_top: Path) -> None:
    """Copy *top* to *shadow_top* so that nothing a step writes there lands outside it.

    - A symbolic link that resolves inside *top* stays a link, to the same place
      in the copy: a relative one as it is, an absolute one rewritten.
    - One that resolves outside *top* (a dotfile manager's ``.mcp.json``, a
      shared ``.vscode``) becomes a copy of what it points at, so a write
      through it changes the copy, and the plan lists it. A dangling one is
      left out: a step then creates the file, as it would through the link.
    - Sockets, FIFOs and device nodes are left out: nothing setup reads is one,
      and copying one fails.
    """
    real_top = top.resolve()
    #: Folders outside the tree copied through a link.
    outside: set[Path] = set()
    copied = [0, 0]

    def count(path: Path) -> None:
        copied[0] += 1
        copied[1] += path.stat().st_size
        if copied[0] > MAX_COPY_FILES or copied[1] > MAX_COPY_BYTES:
            raise PlanRefused(
                f"--plan copies the work tree around the target into a temporary folder, "
                f"and {top} holds more than {MAX_COPY_FILES:,} files or "
                f"{MAX_COPY_BYTES // (1024 * 1024)} MB outside the folders it skips. "
                "Plan a smaller tree with --path, or run setup without --plan."
            )

    def copy_link(source: Path, dest: Path) -> None:
        try:
            resolved = source.resolve(strict=True)
        except (OSError, RuntimeError):
            resolved = None
        raw = os.readlink(source)
        if resolved is None:
            # Dangling: keep a relative link that stays inside the copy.
            lexical = Path(os.path.normpath(source.parent / raw))
            if not Path(raw).is_absolute() and lexical.is_relative_to(top):
                os.symlink(raw, dest)
            return
        if resolved.is_relative_to(real_top):
            if Path(raw).is_absolute():
                os.symlink(shadow_top / resolved.relative_to(real_top), dest)
            else:
                os.symlink(raw, dest)
            return
        if resolved.is_dir():
            # A folder above the tree, or one copied already, would never end.
            if real_top.is_relative_to(resolved) or resolved in outside:
                return
            outside.add(resolved)
            copy_dir(resolved, dest)
        elif resolved.is_file():
            count(resolved)
            shutil.copy2(resolved, dest)

    def copy_dir(source: Path, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        try:
            entries = sorted(os.scandir(source), key=lambda entry: entry.name)
        except OSError:
            return
        for entry in entries:
            if entry.name in SKIPPED_DIRS or entry.name == ".git":
                continue
            path = Path(entry.path)
            target = dest / entry.name
            try:
                if entry.is_symlink():
                    copy_link(path, target)
                elif entry.is_dir(follow_symlinks=False):
                    copy_dir(path, target)
                elif entry.is_file(follow_symlinks=False):
                    count(path)
                    shutil.copy2(path, target, follow_symlinks=False)
                # Anything else (socket, FIFO, device) is not copied.
            except OSError:
                # Unreadable: a step cannot read it in the repository either.
                continue

    copy_dir(top, shadow_top)


def stamps(root: Path) -> dict[str, Stamp]:
    """Every file under *root*, by its path relative to *root*: size and mtime.

    ``.git/objects`` is left out: it is the real store's alternate, never written.
    """
    found: dict[str, Stamp] = {}
    git_dir = root / ".git"
    for directory, dirs, files in os.walk(root):
        here = Path(directory)
        dirs[:] = [
            name
            for name in dirs
            if name not in SKIPPED_DIRS and not (here == git_dir and name == "objects")
        ]
        for name in files:
            path = here / name
            try:
                stat = path.lstat()
            except OSError:
                continue
            found[path.relative_to(root).as_posix()] = (stat.st_size, stat.st_mtime_ns)
    return found


def _refuse_to_copy(top: Path) -> None:
    """Refuse a tree no plan should copy: a home folder or a file system root."""
    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        home = None
    if top.parent == top or (home is not None and top.resolve() == home):
        where = "your home folder" if top.parent != top else "a file system root"
        raise PlanRefused(
            f"--plan would copy {where} ({top}) into a temporary folder, its secrets "
            "included. Point --path at the detection repository, or run `git init` "
            "in it so the plan copies that repository alone."
        )


class Sandbox:
    """A copy of the repository around *target*, and the way back to real paths."""

    def __init__(self, target: Path, root: Path) -> None:
        self.real_target = target.resolve() if target.exists() else target.absolute()
        anchor = _nearest_existing(self.real_target)
        top = _git_root(anchor)
        if top is None or not self.real_target.is_relative_to(top):
            top = self.real_target
        _refuse_to_copy(top)
        self.real_top = top
        self.shadow_top = root / (top.name or "repo")
        self.shadow_target = self.shadow_top / self.real_target.relative_to(top)
        if top.is_dir():
            _copy_tree(top, self.shadow_top)
            _copy_git(top, self.shadow_top)
        else:
            self.shadow_top.mkdir(parents=True)
        self._seen = stamps(self.shadow_top)
        self._written: set[str] = set()

    def real_path(self, relative: str) -> Path:
        return self.real_top / relative

    def shown(self, relative: str) -> str:
        """*relative* (to the copy's top) as the plan shows it: relative to the target."""
        path = self.real_path(relative)
        try:
            return path.relative_to(self.real_target).as_posix()
        except ValueError:
            return Path(os.path.relpath(path, self.real_target)).as_posix()

    def step(self, name: str, result: Mapping[str, Any]) -> PlannedStep:
        """What the step that just ran wrote: the files that changed since the last one."""
        now = stamps(self.shadow_top)
        planned = PlannedStep(name, warnings=[self.to_real(str(w)) for w in _warnings(result)])
        shown: set[str] = set()
        for relative in sorted(now):
            if now[relative] == self._seen.get(relative):
                continue
            existed = relative in self._seen or (self.real_path(relative)).exists()
            action: PlanAction = "merge" if existed else "create"
            planned.files.append(PlannedFile(self.shown(relative), action))
            shown.add(self.shown(relative))
            self._written.add(relative)
        for relative in sorted(set(self._seen) - set(now)):
            # A file the step removed (a skill folder replaced whole).
            planned.files.append(PlannedFile(self.shown(relative), "delete"))
            shown.add(self.shown(relative))
        for item in _reported_skips(result):
            path = self.to_real(item)
            relative = self._relative_to_target(path)
            if relative not in shown:
                planned.files.append(PlannedFile(relative, "skip"))
                shown.add(relative)
        self._seen = now
        return planned

    def _relative_to_target(self, reported: str) -> str:
        """A path a step reported (relative to the target, or absolute) as the plan shows it."""
        path = Path(reported)
        if not path.is_absolute():
            return path.as_posix()
        try:
            return path.relative_to(self.real_target).as_posix()
        except ValueError:
            return Path(os.path.relpath(path, self.real_target)).as_posix()

    def to_real(self, text: str) -> str:
        """*text* with the copy's paths replaced by the repository's."""
        for shadow, real in (
            (str(self.shadow_target), str(self.real_target)),
            (str(self.shadow_top), str(self.real_top)),
        ):
            text = text.replace(shadow, real)
        return text


def _warnings(result: Mapping[str, Any]) -> list[str]:
    warnings = result.get("warnings")
    return [str(item) for item in warnings] if isinstance(warnings, list) else []


def _reported_skips(result: Mapping[str, Any]) -> list[str]:
    skipped = result.get("skipped")
    return [str(item) for item in skipped] if isinstance(skipped, list) else []


@contextmanager
def _exit_on_termination() -> Generator[None, None, None]:
    """Turn SIGTERM and SIGHUP into ``SystemExit`` while the copy exists.

    Python's default for both ends the process without running ``finally``
    blocks, so the copy, the repository's secrets included, stayed in the
    temporary folder when an editor or a CI timeout stopped the plan.
    Only the main thread can install handlers; elsewhere this does nothing.
    """
    import signal
    import threading

    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def stop(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    names = [name for name in ("SIGTERM", "SIGHUP") if hasattr(signal, name)]
    previous = {name: signal.signal(getattr(signal, name), stop) for name in names}
    try:
        yield
    finally:
        for name, handler in previous.items():
            # None: a handler installed outside Python, which cannot be put back.
            signal.signal(getattr(signal, name), signal.SIG_DFL if handler is None else handler)


@contextmanager
def sandbox(target: Path) -> Generator[Sandbox, None, None]:
    """A :class:`Sandbox` for *target*, with the workspace variables pointing at the copy."""
    saved = {name: os.environ.get(name) for name in (*_WORKSPACE_VARIABLES, *_GIT_VARIABLES)}
    with (
        _exit_on_termination(),
        tempfile.TemporaryDirectory(prefix="opentide-setup-plan-") as scratch,
    ):
        box = Sandbox(target, Path(scratch))
        for name in _GIT_VARIABLES:
            os.environ.pop(name, None)
        for name in _WORKSPACE_VARIABLES:
            # Whatever a step reads through the workspace root must be the copy.
            os.environ[name] = str(box.shadow_target)
        from opentide.core.root import get_repo_root

        get_repo_root.cache_clear()
        try:
            yield box
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
            get_repo_root.cache_clear()


def plan_payload(
    target: Path,
    steps: Iterable[PlannedStep],
    *,
    warnings: Iterable[str] = (),
) -> dict[str, object]:
    """The ``--plan`` document: each step's files, the counts, and the outcome line."""
    listed = list(steps)
    counts = {"create": 0, "merge": 0, "skip": 0, "delete": 0}
    for step in listed:
        for item in step.files:
            counts[item.action] += 1
    all_warnings: list[str] = []
    for warning in [*warnings, *(w for step in listed for w in step.warnings)]:
        if warning not in all_warnings:
            all_warnings.append(warning)
    writes = counts["create"] + counts["merge"]
    noun = "file" if writes == 1 else "files"
    removed = f", {counts['delete']} to remove" if counts["delete"] else ""
    message = (
        f"Plan: {writes} {noun} to write ({counts['create']} new, {counts['merge']} changed)"
        f"{removed} · nothing written"
    )
    return {
        "message": message,
        "status": "completed",
        "plan": True,
        "path": str(target.resolve() if target.exists() else target.absolute()),
        "steps": [step.to_dict() for step in listed],
        "warnings": all_warnings,
        "_summary": {**counts, "steps": len(listed)},
        "_outcome_kind": "plan",
    }


def plan_steps(
    target: Path,
    run: Callable[[Path, Callable[[str, Mapping[str, Any]], None]], Mapping[str, Any]],
    *,
    name: str,
) -> tuple[list[PlannedStep], Mapping[str, Any]]:
    """Run *run* in a sandbox of *target*; return the planned steps and its result.

    *run* gets the copy of the target and a callback to call after each step
    with the step's name and result (``run_setup`` does it for each of its
    steps). A run that never calls it is one step, *name*.
    """
    planned: list[PlannedStep] = []
    with sandbox(target) as box:

        def after_step(step: str, result: Mapping[str, Any]) -> None:
            planned.append(box.step(step, result))

        result = run(box.shadow_target, after_step)
        if not planned:
            planned.append(box.step(name, result))
    return planned, result
