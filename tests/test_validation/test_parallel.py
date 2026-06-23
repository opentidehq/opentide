"""Parallel validation helpers."""

from __future__ import annotations

from opentide.validation.issues import ValidationIssue
from opentide.validation.parallel import (
    map_parallel,
    max_workers_cap,
    parallel_threshold,
    resolve_worker_count,
    sort_issues,
)


def test_resolve_worker_count_sequential_below_threshold(monkeypatch) -> None:
    monkeypatch.setenv("OPENTIDE_VALIDATE_PARALLEL_THRESHOLD", "10")
    assert resolve_worker_count(5) == 0


def test_resolve_worker_count_parallel_above_threshold(monkeypatch) -> None:
    monkeypatch.setenv("OPENTIDE_VALIDATE_PARALLEL_THRESHOLD", "2")
    monkeypatch.setenv("OPENTIDE_VALIDATE_WORKERS", "4")
    assert resolve_worker_count(8) == 4


def test_resolve_worker_count_force_sequential() -> None:
    assert resolve_worker_count(100, workers=0) == 0


def test_resolve_worker_count_explicit_workers() -> None:
    assert resolve_worker_count(100, workers=3) == 3


def test_map_parallel_matches_sequential() -> None:
    items = list(range(12))

    def _double(n: int) -> list[ValidationIssue]:
        return [
            ValidationIssue(
                code="test",
                object_uuid=str(n),
                message=f"item-{n}",
            )
        ]

    sequential = [issue for item in items for issue in _double(item)]
    parallel = map_parallel(_double, items, workers=4)
    assert {issue.object_uuid for issue in parallel} == {issue.object_uuid for issue in sequential}


def test_sort_issues_stable_order() -> None:
    issues = [
        ValidationIssue(code="b", object_uuid="2", message="second"),
        ValidationIssue(code="a", object_uuid="1", message="first"),
    ]
    sorted_issues = sort_issues(issues)
    assert sorted_issues[0].object_uuid == "1"
    assert sorted_issues[1].object_uuid == "2"


def test_parallel_defaults() -> None:
    assert parallel_threshold() >= 1
    assert max_workers_cap() >= 1
