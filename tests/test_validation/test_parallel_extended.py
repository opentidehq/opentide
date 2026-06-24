"""Extended parallel validation helper coverage."""

from __future__ import annotations

from pathlib import Path

from opentide.validation.issues import ValidationIssue
from opentide.validation.parallel import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_PARALLEL_THRESHOLD,
    map_parallel,
    max_workers_cap,
    parallel_threshold,
    resolve_worker_count,
    sort_issues,
)


def test_parallel_threshold_defaults_and_env(monkeypatch) -> None:
    monkeypatch.delenv("OPENTIDE_VALIDATE_PARALLEL_THRESHOLD", raising=False)
    assert parallel_threshold() == DEFAULT_PARALLEL_THRESHOLD
    monkeypatch.setenv("OPENTIDE_VALIDATE_PARALLEL_THRESHOLD", "4")
    assert parallel_threshold() == 4
    monkeypatch.setenv("OPENTIDE_VALIDATE_PARALLEL_THRESHOLD", "0")
    assert parallel_threshold() == 1


def test_max_workers_cap_defaults_and_env(monkeypatch) -> None:
    monkeypatch.delenv("OPENTIDE_VALIDATE_WORKERS", raising=False)
    assert max_workers_cap() == DEFAULT_MAX_WORKERS
    monkeypatch.setenv("OPENTIDE_VALIDATE_WORKERS", "auto")
    assert max_workers_cap() == DEFAULT_MAX_WORKERS
    monkeypatch.setenv("OPENTIDE_VALIDATE_WORKERS", "3")
    assert max_workers_cap() == 3


def test_resolve_worker_count_branches(monkeypatch) -> None:
    assert resolve_worker_count(0) == 0
    assert resolve_worker_count(5, workers=0) == 0
    assert resolve_worker_count(100, workers=2) == 2
    monkeypatch.setenv("OPENTIDE_VALIDATE_PARALLEL_THRESHOLD", "10")
    assert resolve_worker_count(5) == 0
    assert resolve_worker_count(50) == min(DEFAULT_MAX_WORKERS, 50)


def test_map_parallel_empty_items() -> None:
    assert map_parallel(lambda _x: [], [], workers=2) == []


def test_map_parallel_thread_pool_collects_issues() -> None:
    def _make_issue(value: int) -> list[ValidationIssue]:
        return [ValidationIssue(code=f"c{value}", message=str(value))]

    issues = map_parallel(_make_issue, [1, 2], workers=2)
    assert len(issues) == 2
    codes = {issue.code for issue in issues}
    assert codes == {"c1", "c2"}


def test_sort_issues_stable_ordering() -> None:
    issues = [
        ValidationIssue(
            code="b",
            message="second",
            file_path="b.yaml",
            yaml_line=2,
            field_path=("f",),
            object_uuid="u2",
        ),
        ValidationIssue(
            code="a",
            message="first",
            file_path="a.yaml",
            yaml_line=1,
            field_path=("f",),
            object_uuid="u1",
        ),
    ]
    sorted_issues = sort_issues(issues)
    assert sorted_issues[0].file_path == Path("a.yaml")
