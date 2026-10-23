"""Generation pipeline services for the CLI."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from opentide.core.index_manager import IndexManager
from opentide.core.registry import Opentide
from opentide.core.root import get_repo_root
from opentide.generation.errors import GenerationPhaseError, failing_phase

logger = structlog.get_logger("opentide.cli.services.generation")

if TYPE_CHECKING:
    from opentide.cli.context import CliContext
    from opentide.cli.ui.progress import Checklist, Step

# User-visible outputs first, then framework internals. Extract is opt-in only.
_PHASE_ORDER: tuple[str, ...] = (
    "docs",
    "exports",
    "vocabs",
    "templates",
    "schemas",
    "snippets",
)


def run_generate_phase(phase: str) -> None:
    """Run a single generation phase."""
    if phase == "vocabs":
        from opentide.indexing.object_vocab import run as generate_object_vocab

        generate_object_vocab()
        return
    if phase == "templates":
        from opentide.generation.template import run as generate_templates

        generate_templates()
        IndexManager.reload()
        Opentide.reload()
        return
    if phase == "schemas":
        from opentide.generation.schema import run as generate_schemas

        generate_schemas()
        IndexManager.reload()
        Opentide.reload()
        return
    if phase == "snippets":
        from opentide.generation.vscode_snippets import run as generate_snippets

        generate_snippets()
        return
    if phase == "exports":
        from opentide.export import attack_navigator_layer
        from opentide.export.revisions_export import run as export_revisions
        from opentide.export.table_export import TableExporter

        attack_navigator_layer.run()
        TableExporter().run()
        export_revisions()
        return
    if phase == "explorer":
        from opentide.export.explorer_export import run as export_explorer

        export_explorer()
        return
    if phase == "inflight":
        from opentide.indexing.inflight import run as generate_inflight

        generate_inflight()
        return
    if phase == "inflight-prune":
        from opentide.indexing.inflight import run_prune as prune_inflight

        prune_inflight()
        return
    if phase == "docs":
        from opentide.documentation.cli import run as run_docs

        run_docs()
        return
    raise ValueError(f"Unknown generation phase: {phase}")


@contextmanager
def workspace_repo_env(target: Path) -> Iterator[Path]:
    """Bind generation/index lookup to ``target`` and restore process state."""
    resolved = target.resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    previous_root = os.environ.get("OPENTIDE_REPO_ROOT")
    previous_workspace = os.environ.get("OPENTIDE_TIDE_WORKSPACE")
    get_repo_root.cache_clear()
    os.environ["OPENTIDE_REPO_ROOT"] = str(resolved)
    os.environ["OPENTIDE_TIDE_WORKSPACE"] = str(resolved)
    IndexManager._cache = None
    cwd_previous = Path.cwd()
    try:
        os.chdir(resolved)
        yield resolved
    finally:
        os.chdir(cwd_previous)
        get_repo_root.cache_clear()
        IndexManager._cache = None
        if previous_root is None:
            os.environ.pop("OPENTIDE_REPO_ROOT", None)
        else:
            os.environ["OPENTIDE_REPO_ROOT"] = previous_root
        if previous_workspace is None:
            os.environ.pop("OPENTIDE_TIDE_WORKSPACE", None)
        else:
            os.environ["OPENTIDE_TIDE_WORKSPACE"] = previous_workspace


def run_generate_phases_for_workspace(target: Path, phases: Sequence[str]) -> list[str]:
    """Run ``run_generate_phase`` for each name with ``OPENTIDE_REPO_ROOT`` set."""
    ran: list[str] = []
    with workspace_repo_env(target):
        for phase in phases:
            run_generate_phase(phase)
            ran.append(phase)
    return ran


#: Directories never scanned for written files: version control, environments, caches.
_SKIPPED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
    }
)

#: Step names as the checklist shows them.
PHASE_LABELS: dict[str, str] = {
    "vocabs": "vocabularies",
    "inflight-prune": "inflight prune",
}


def _snapshot(roots: Sequence[Path]) -> dict[str, tuple[int, int]]:
    """``path → (mtime_ns, size)`` for every file under *roots*."""
    seen: dict[str, tuple[int, int]] = {}
    pending = [root for root in roots if root.is_dir()]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in _SKIPPED_DIRS:
                        pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    stat = entry.stat(follow_symlinks=False)
                    seen[entry.path] = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                continue
    return seen


class WrittenFiles:
    """The files a step wrote and removed, found by comparing the tree before and after.

    The generators write with plain ``Path.write_text``; comparing modification
    times and sizes counts their output without touching every writer.
    """

    def __init__(self, *roots: Path) -> None:
        self.roots = tuple(dict.fromkeys(root.resolve() for root in roots))
        self.started_ns = time.time_ns()
        self.before = _snapshot(self.roots)

    def changes(self) -> tuple[list[Path], list[Path]]:
        after = _snapshot(self.roots)
        written = [
            Path(path)
            for path, stamp in after.items()
            if self.before.get(path) != stamp or stamp[0] >= self.started_ns
        ]
        removed = [Path(path) for path in self.before if path not in after]
        return sorted(written), sorted(removed)


def _common_dir(paths: Sequence[Path], workspace: Path) -> str | None:
    """The directory holding every path, as the reader sees it (``.opentide/schemas/``)."""
    from opentide.cli.ui.paths import display_path

    if not paths:
        return None
    common = Path(os.path.commonpath([str(path.parent) for path in paths]))
    return display_path(common, workspace=workspace)


def _scan_roots(workspace: Path, *extra: str | None) -> list[Path]:
    roots = [workspace]
    for item in extra:
        if item:
            path = Path(item)
            roots.append(path if path.is_absolute() else workspace / path)
    return roots


@contextmanager
def generation_step(
    checklist: Checklist, phase: str, *, outputs: Sequence[str | None] = ()
) -> Iterator[Step]:
    """Run one generation phase as a checklist step that counts the files it wrote."""
    workspace = get_repo_root().resolve()
    watch = WrittenFiles(*_scan_roots(workspace, *outputs))
    with checklist.step(PHASE_LABELS.get(phase, phase)) as step:
        yield step
        written, removed = watch.changes()
        if removed and not written:
            step.done(len(removed), where=_common_dir(removed, workspace), detail="removed")
            step.unit = "file removed"
        else:
            step.done(len(written), where=_common_dir(written, workspace))


def generation_result(
    checklist: Checklist, message: str | None = None, **data: object
) -> dict[str, object]:
    """``Generated 28 files in 4.8s · 6 phases``, with the counts and steps behind it."""
    from opentide.cli.ui.progress import plural, seconds_text

    steps = checklist.steps
    written = sum(step.count or 0 for step in steps if step.unit == "file")
    removed = sum(step.count or 0 for step in steps if step.unit == "file removed")
    seconds = sum(step.seconds for step in steps)
    if message is None:
        subject = (
            f"{plural(len(steps), 'phase')}"
            if len(steps) != 1
            else steps[0].name
            if steps
            else "nothing to run"
        )
        if removed and not written:
            message = f"Removed {plural(removed, 'file')} in {seconds_text(seconds)} · {subject}"
        else:
            message = f"Generated {plural(written, 'file')} in {seconds_text(seconds)} · {subject}"
    return {
        "message": message,
        **data,
        "steps": [step.to_dict() for step in steps],
        "_summary": {
            "files": written,
            "removed": removed,
            "phases": len(steps),
            "seconds": round(seconds, 3),
        },
    }


def run_generate_docs(
    *,
    output: str | None = None,
    flavor: str | None = None,
    rules: bool = False,
    threats: bool = False,
    objectives: bool = False,
    changed: bool = False,
    scope: str | None = None,
) -> dict[str, object]:
    from opentide.cli.ui.progress import Checklist
    from opentide.documentation.cli import run as run_docs
    from opentide.documentation.types import DocumentScope

    if changed and (scope is not None or rules or threats or objectives):
        raise ValueError("--changed cannot be combined with scoped docs generation")
    if scope != DocumentScope.index.value:
        if rules:
            scope = DocumentScope.rules.value
        elif threats:
            scope = DocumentScope.threats.value
        elif objectives:
            scope = DocumentScope.objectives.value
    try:
        with Checklist(total=1) as checklist, generation_step(checklist, "docs", outputs=(output,)):
            with failing_phase("docs"):
                result = dict(run_docs(scope=scope, output=output, flavor=flavor, changed=changed))
    except GenerationPhaseError as exc:
        return phase_failure(exc)
    if result.get("status") == "failed":
        return result
    return {**result, **generation_result(checklist, **_without_message(result))}


def _without_message(result: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in result.items() if key != "message"}


def run_generate_all(checklist: Checklist | None = None) -> None:
    """Run the full generation pipeline, reporting what each phase costs.

    A run that overruns a CI job timeout is otherwise undiagnosable: the
    output carries no phase boundary and no timing, so there is no way to
    tell from a killed job whether it was 10% or 90% through, or which
    phase consumed the budget.
    """
    from opentide.cli.ui.progress import Checklist

    owned = checklist is None
    checklist = checklist or Checklist(total=len(_PHASE_ORDER))
    elapsed: dict[str, float] = {}
    started = time.monotonic()
    if owned:
        checklist.__enter__()
    try:
        for phase in _PHASE_ORDER:
            phase_started = time.monotonic()
            try:
                with generation_step(checklist, phase), failing_phase(phase):
                    run_generate_phase(phase)
            finally:
                # Timed in `finally` so a phase that raises still reports its
                # cost -- that reading is exactly what a killed job needs.
                elapsed[phase] = time.monotonic() - phase_started
                logger.info(
                    "generation_phase_complete",
                    phase=phase,
                    seconds=round(elapsed[phase], 1),
                )
    finally:
        if owned:
            checklist.__exit__(None, None, None)
    total = time.monotonic() - started
    logger.info(
        "generation_complete",
        seconds=round(total, 1),
        phases={name: round(value, 1) for name, value in elapsed.items()},
        slowest=max(elapsed, key=lambda name: elapsed[name]) if elapsed else None,
    )


def run_generate(
    ctx: CliContext,
    *,
    phase: str | None = None,
    phases: Sequence[str] | None = None,
) -> dict[str, object]:
    """Entry point for generate command.

    The result's ``message`` is the outcome line (``Generated 28 files in 4.8s
    · 6 phases``); ``steps`` and ``_summary`` carry the counts behind it.
    """
    from opentide.cli.ui.progress import Checklist

    ctx.apply_environment()
    names = list(phases) if phases else list(_PHASE_ORDER) if phase is None else [phase]
    try:
        with Checklist(total=len(names)) as checklist:
            if phases:
                for name in phases:
                    with generation_step(checklist, name), failing_phase(name):
                        run_generate_phase(name)
            elif phase is None:
                run_generate_all(checklist)
            else:
                with generation_step(checklist, phase), failing_phase(phase):
                    run_generate_phase(phase)
    except GenerationPhaseError as exc:
        return phase_failure(exc)
    if phases:
        return generation_result(checklist, phases=list(phases))
    if phase is None:
        return generation_result(checklist, phases=list(_PHASE_ORDER))
    return generation_result(checklist, phase=phase)


def phase_failure(exc: GenerationPhaseError) -> dict[str, object]:
    """The failed result for a phase: exit ``1``, and the phase named twice.

    Once in ``phase`` for automation, once leading ``message`` for a person.
    """
    return {"message": str(exc), "status": "failed", "phase": exc.phase, "_exit_code": 1}
