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
  as it does in the repository (branches, ``core.hooksPath``); a linked
  worktree's or a submodule's ``.git`` file keeps its layout, and its links are
  copied as the work tree's are (:func:`_copy_git`).

A step that would write outside the repository (a ``core.hooksPath`` shared
with other repositories) writes nothing there in a plan either: it warns, as
it does when it runs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
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


def _copy_git(top: Path, shadow_top: Path, scratch: Path) -> list[tuple[Path, Path]]:
    """A ``.git`` in the copy that ``git`` reads as the real one, sharing its objects.

    The copy keeps the repository's layout. A plain ``.git`` folder is copied
    into the copy's top. A ``.git`` file (a linked worktree, a submodule) stays
    a file, pointing at a copy of its git directory beside the copy, whose
    ``commondir`` points at a copy of the common directory: so the hooks of a
    worktree land in the common directory, as they do for real, and a
    submodule's ``core.worktree`` no longer points out of the copy.

    Returns the ``(copy, repository)`` pairs of the git directories kept
    outside the copy's top, for :class:`Sandbox` to watch and map back.
    """
    found = _git_dirs(top)
    if found is None:
        return []
    git_dir, common = found
    roots: list[tuple[Path, Path]] = []
    if (top / ".git").is_dir() and git_dir == common:
        shadow_git = shadow_common = shadow_top / ".git"
    else:
        shadow_common = scratch / "git-common"
        roots.append((shadow_common, common))
        shadow_git = shadow_common
        if git_dir != common:
            shadow_git = scratch / "git-dir"
            roots.append((shadow_git, git_dir))
    shadow_git.mkdir(parents=True, exist_ok=True)
    shadow_common.mkdir(parents=True, exist_ok=True)
    head = git_dir / "HEAD"
    if head.is_file():
        shutil.copy2(head, shadow_git / "HEAD")
    if shadow_git != shadow_common:
        (shadow_git / "commondir").write_text(f"{shadow_common}\n", encoding="utf-8")
        worktree_config = git_dir / "config.worktree"
        if worktree_config.is_file():
            shutil.copy2(worktree_config, shadow_git / "config.worktree")
    if roots:
        (shadow_top / ".git").write_text(f"gitdir: {shadow_git}\n", encoding="utf-8")
    for name in _GIT_FILES[1:]:
        source = common / name
        if source.is_file():
            shutil.copy2(source, shadow_common / name)
    # Links as in the work tree: a hook linked to the repository's versioned one, or to a
    # shared folder, must not be written through (``setup hooks`` follows the link).
    copier = _Copier(top, [(top, shadow_top), (common, shadow_common)])
    for name in _GIT_DIRS:
        source = common / name
        if source.is_dir():
            copier.copy_dir(source, shadow_common / name, home=common)
    objects = shadow_common / "objects"
    (objects / "info").mkdir(parents=True, exist_ok=True)
    (objects / "pack").mkdir(exist_ok=True)
    real_objects = common / "objects"
    if real_objects.is_dir():
        (objects / "info" / "alternates").write_text(f"{real_objects}\n", encoding="utf-8")
    config = shadow_common / "config"
    if config.is_file() and roots:
        # A submodule's points back at the real work tree: the copy's is where its .git is.
        _git("config", "--file", str(config), "--unset", "core.worktree")
    _pin_hooks_path(top, shadow_top, config)
    return roots


def _git(*args: str) -> subprocess.CompletedProcess[str] | None:
    """``git *args*`` with no inherited ``GIT_DIR`` and friends; ``None`` without Git."""
    env = {name: value for name, value in os.environ.items() if name not in _GIT_VARIABLES}
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True, check=False, env=env)
    except OSError:
        return None


def _pin_hooks_path(top: Path, shadow_top: Path, config: Path) -> None:
    """Give the copy the ``core.hooksPath`` the repository has, mapped into the copy.

    Read from the repository, so a value set by an ``includeIf "gitdir:…"`` that
    matches the real path but not the copy's still applies. An absolute path
    inside the repository (``$PWD/.githooks``) would point the copy back at
    the repository, where the hooks step sees a folder outside its tree and
    leaves it alone as shared: it becomes the same folder in the copy.
    """
    probe = _git("-C", str(top), "config", "--get", "core.hooksPath")
    if probe is None or probe.returncode != 0 or not probe.stdout.strip():
        return
    value = probe.stdout.strip()
    path = Path(os.path.expanduser(value))
    if path.is_absolute():
        resolved = path.resolve()
        real_top = top.resolve()
        if resolved.is_relative_to(real_top):
            value = str(shadow_top / resolved.relative_to(real_top))
    if config.is_file():
        _git("config", "--file", str(config), "core.hooksPath", value)


class _Copier:
    """Copies folders into the plan's copy so that nothing a step writes there lands outside it.

    *maps* pairs each real folder the copy mirrors (the work tree's top, a git
    directory) with its place in the copy.

    - A symbolic link that resolves inside one of them stays a link, to the same
      place in the copy: a relative one inside the folder it is copied with as it
      is, any other rewritten to an absolute link into the copy.
    - One that resolves outside them (a dotfile manager's ``.mcp.json``, a shared
      ``.vscode``, a shared hook) becomes a copy of what it points at, so a write
      through it changes the copy, and the plan lists it. A dangling one is left
      out: a step then creates the file, as it would through the link.
    - Sockets, FIFOs and device nodes are left out: nothing setup reads is one,
      and copying one fails.
    """

    def __init__(self, top: Path, maps: Iterable[tuple[Path, Path]]) -> None:
        self.top = top
        # Longest first: a git directory inside the work tree is its own mapping.
        self.maps = sorted(
            ((real.resolve(), shadow) for real, shadow in maps),
            key=lambda pair: len(pair[0].parts),
            reverse=True,
        )
        #: Folders outside the mapped ones, copied through a link.
        self.outside: set[Path] = set()
        self.files = 0
        self.bytes = 0

    def count(self, path: Path) -> None:
        self.files += 1
        self.bytes += path.stat().st_size
        if self.files > MAX_COPY_FILES or self.bytes > MAX_COPY_BYTES:
            raise PlanRefused(
                f"--plan copies the work tree around the target into a temporary folder, "
                f"and {self.top} holds more than {MAX_COPY_FILES:,} files or "
                f"{MAX_COPY_BYTES // (1024 * 1024)} MB outside the folders it skips. "
                "Plan a smaller tree with --path, or run setup without --plan."
            )

    def _mapped(self, resolved: Path) -> tuple[Path, Path] | None:
        for real, shadow in self.maps:
            if resolved.is_relative_to(real):
                return real, shadow
        return None

    def copy_link(self, source: Path, dest: Path, home: Path) -> None:
        """Copy the link *source*, found while copying the real folder *home*, to *dest*."""
        try:
            resolved = source.resolve(strict=True)
        except (OSError, RuntimeError):
            resolved = None
        raw = os.readlink(source)
        if resolved is None:
            # Dangling: keep a relative link that stays inside the copy.
            lexical = Path(os.path.normpath(source.parent / raw))
            if not Path(raw).is_absolute() and lexical.is_relative_to(home):
                os.symlink(raw, dest)
            return
        mapped = self._mapped(resolved)
        if mapped is not None:
            real, shadow = mapped
            if not Path(raw).is_absolute() and real == home.resolve():
                os.symlink(raw, dest)
            else:
                os.symlink(shadow / resolved.relative_to(real), dest)
            return
        if resolved.is_dir():
            # A folder above a mapped one, or one copied already, would never end.
            if any(real.is_relative_to(resolved) for real, _ in self.maps):
                return
            if resolved in self.outside:
                return
            self.outside.add(resolved)
            self.copy_dir(resolved, dest, home=resolved)
        elif resolved.is_file():
            self.count(resolved)
            shutil.copy2(resolved, dest)

    def copy_dir(
        self,
        source: Path,
        dest: Path,
        *,
        home: Path,
        skipped: frozenset[str] = frozenset(),
        keep: frozenset[Path] = frozenset(),
    ) -> None:
        """Copy *source* to *dest*, leaving out folders named in *skipped* unless in *keep*."""
        dest.mkdir(parents=True, exist_ok=True)
        try:
            entries = sorted(os.scandir(source), key=lambda entry: entry.name)
        except OSError:
            return
        for entry in entries:
            path = Path(entry.path)
            if entry.name in skipped and path not in keep:
                continue
            target = dest / entry.name
            try:
                if entry.is_symlink():
                    self.copy_link(path, target, home)
                elif entry.is_dir(follow_symlinks=False):
                    self.copy_dir(path, target, home=home, skipped=skipped, keep=keep)
                elif entry.is_file(follow_symlinks=False):
                    self.count(path)
                    shutil.copy2(path, target, follow_symlinks=False)
                # Anything else (socket, FIFO, device) is not copied.
            except OSError:
                # Unreadable: a step cannot read it in the repository either.
                continue


def _ancestry(top: Path, target: Path) -> frozenset[Path]:
    """*target* and its folders up to *top*: never left out, whatever their name."""
    if not target.is_relative_to(top):
        return frozenset()
    return frozenset({target, *(p for p in target.parents if p.is_relative_to(top))})


def _copy_tree(top: Path, shadow_top: Path, target: Path | None = None) -> None:
    """Copy the work tree *top* to *shadow_top*, less ``.git`` and the folders no step reads.

    A folder on the way to *target* is copied even when it is named like build
    output (a detection repository in ``build/detections`` of a monorepo).
    """
    _Copier(top, [(top, shadow_top)]).copy_dir(
        top,
        shadow_top,
        home=top,
        skipped=SKIPPED_DIRS | {".git"},
        keep=_ancestry(top, target if target is not None else top),
    )


def stamps(root: Path, *git_dirs: Path, target: Path | None = None) -> dict[str, Stamp]:
    """Every file under *root* and *git_dirs*, by its absolute path: size and mtime.

    ``objects`` of ``root/.git`` and of each git directory is left out: it is
    the real store's alternate, never written. So are the folders the copy
    leaves out, except those on the way to *target*.
    """
    found: dict[str, Stamp] = {}
    skipped = {root / ".git" / "objects", *(folder / "objects" for folder in git_dirs)}
    keep = _ancestry(root, target if target is not None else root)
    for top in (root, *git_dirs):
        for directory, dirs, files in os.walk(top):
            here = Path(directory)
            dirs[:] = [
                name
                for name in dirs
                if (name not in SKIPPED_DIRS or here / name in keep) and here / name not in skipped
            ]
            for name in files:
                path = here / name
                try:
                    stat = path.lstat()
                except OSError:
                    continue
                found[str(path)] = (stat.st_size, stat.st_mtime_ns)
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
        #: ``(copy, repository)`` folder pairs: the copy's top, then any git
        #: directory kept beside it (:func:`_copy_git`).
        self._roots: list[tuple[Path, Path]] = [(self.shadow_top, top)]
        if top.is_dir():
            _copy_tree(top, self.shadow_top, self.real_target)
            self._roots.extend(_copy_git(top, self.shadow_top, root))
        else:
            self.shadow_top.mkdir(parents=True)
        self._seen = self._stamps()
        self._written: set[str] = set()

    def _stamps(self) -> dict[str, Stamp]:
        return stamps(
            self.shadow_top,
            *(shadow for shadow, _ in self._roots[1:]),
            target=self.shadow_target,
        )

    def real_path(self, shadow: str) -> Path:
        """The repository's path for *shadow*, a path in the copy (or relative to its top)."""
        path = Path(shadow)
        if not path.is_absolute():
            return self.real_top / path
        for copy, real in self._roots:
            if path.is_relative_to(copy):
                return real / path.relative_to(copy)
        return path

    def shown(self, shadow: str) -> str:
        """*shadow* (a path in the copy) as the plan shows it: relative to the target."""
        path = self.real_path(shadow)
        try:
            return path.relative_to(self.real_target).as_posix()
        except ValueError:
            return Path(os.path.relpath(path, self.real_target)).as_posix()

    def step(self, name: str, result: Mapping[str, Any]) -> PlannedStep:
        """What the step that just ran wrote: the files that changed since the last one."""
        now = self._stamps()
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
        pairs = [
            (str(self.shadow_target), str(self.real_target)),
            *((str(copy), str(real)) for copy, real in self._roots),
        ]
        # Longest first: the target sits inside the copy's top.
        for shadow, real in sorted(pairs, key=lambda pair: len(pair[0]), reverse=True):
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

    The result's ``warnings`` name the repository's paths, not the copy's.

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
        # The run's own warnings (flags it ignored), with the copy's paths made real.
        result = {**result, "warnings": [box.to_real(warning) for warning in _warnings(result)]}
    return planned, result
