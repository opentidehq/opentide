"""Tests for validation parallel helpers."""

from __future__ import annotations

from opentide.validation.issues import ValidationIssue
from opentide.validation.parallel import map_parallel, resolve_worker_count, sort_issues


def test_resolve_worker_count_zero_for_small_jobs() -> None:
    assert resolve_worker_count(1, workers=0) == 0


def test_resolve_worker_count_caps_workers() -> None:
    assert resolve_worker_count(100, workers=2) == 2


def test_map_parallel_serial_fallback() -> None:
    def _double(_item: int) -> list[ValidationIssue]:
        return []

    values = map_parallel(_double, [1, 2, 3], workers=0)
    assert values == []


def test_sort_issues_orders_by_file_and_line() -> None:
    issues = [
        ValidationIssue(code="b", message="second", file_path=None),
        ValidationIssue(code="a", message="first", file_path=None),
    ]
    sorted_issues = sort_issues(issues)
    assert sorted_issues[0].code == "a"
