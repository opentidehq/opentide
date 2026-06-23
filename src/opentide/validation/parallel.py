"""Thread-pool helpers for parallel validation sessions."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

from opentide.validation.issues import ValidationIssue

T = TypeVar("T")

DEFAULT_PARALLEL_THRESHOLD = 32
DEFAULT_MAX_WORKERS = min(32, (os.cpu_count() or 4) + 4)


def parallel_threshold() -> int:
    """Minimum object count before enabling parallel validation."""
    raw = os.environ.get("OPENTIDE_VALIDATE_PARALLEL_THRESHOLD")
    if raw is None:
        return DEFAULT_PARALLEL_THRESHOLD
    return max(1, int(raw))


def max_workers_cap() -> int:
    """Upper bound on worker threads (``auto`` when env unset)."""
    raw = os.environ.get("OPENTIDE_VALIDATE_WORKERS")
    if raw is None or raw.lower() == "auto":
        return DEFAULT_MAX_WORKERS
    return max(1, int(raw))


def resolve_worker_count(item_count: int, *, workers: int | None = None) -> int:
    """Return worker count; ``0`` means run sequentially."""
    if item_count <= 0:
        return 0
    if workers == 0:
        return 0
    if workers is not None and workers > 0:
        return min(workers, item_count)
    if item_count < parallel_threshold():
        return 0
    return min(max_workers_cap(), item_count)


def map_parallel(
    func: Callable[[T], list[ValidationIssue]],
    items: Iterable[T],
    *,
    workers: int,
) -> list[ValidationIssue]:
    """Apply *func* to each item, using a thread pool when *workers* > 0."""
    item_list = list(items)
    if not item_list:
        return []
    if workers <= 0:
        return [issue for item in item_list for issue in func(item)]

    issues: list[ValidationIssue] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for batch in pool.map(func, item_list):
            issues.extend(batch)
    return issues


def sort_issues(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    """Stable ordering for deterministic CLI/CI output."""
    return sorted(
        issues,
        key=lambda issue: (
            str(issue.file_path or ""),
            issue.yaml_line if issue.yaml_line is not None else -1,
            issue.field_path,
            issue.object_uuid,
            issue.code,
            issue.message,
        ),
    )
