"""The language server's cold-start gate (scripts/perf/check_cold_start.py, #1754).

The checker holds each scenario's p50 to its budget with the headroom of
tests/bench/budgets.toml's [policy], and fails a scenario that has no report, a
report with failed runs, or a report no scenario budgets.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
_MODULE = ROOT / "scripts" / "perf" / "check_cold_start.py"
_spec = importlib.util.spec_from_file_location("check_cold_start", _MODULE)
assert _spec
assert _spec.loader
cold = importlib.util.module_from_spec(_spec)
sys.modules["check_cold_start"] = cold  # a dataclass of the module looks itself up here
_spec.loader.exec_module(cold)

BUDGETS = ROOT / "tests" / "bench" / "lsp-cold-start.toml"
POLICY = ROOT / "tests" / "bench" / "budgets.toml"


def _budgets(tmp_path: Path, *scenarios: tuple[str, float], runs: int = 10) -> Path:
    path = tmp_path / "budgets.toml"
    body = [f"schema_version = 1\nruns = {runs}\n"]
    body.extend(
        f'[[scenario]]\nid = "{sid}"\nlabel = "{sid}"\nbudget_ms = {ms}\n' for sid, ms in scenarios
    )
    path.write_text("\n".join(body), encoding="utf-8")
    return path


def _report(reports: Path, sid: str, p50: float | None, *, runs: int = 10, failed: int = 0) -> None:
    reports.mkdir(exist_ok=True)
    report: dict[str, Any] = {
        "label": sid,
        "runs": runs,
        "failed": failed,
        "machine": {"model": "Test CPU"},
        "summary": {"start_to_first_diag_ms": {"p50": p50}},
    }
    (reports / f"{sid}.json").write_text(json.dumps(report), encoding="utf-8")


def test_the_headroom_is_the_benchmarks_policy() -> None:
    policy = cold.load_policy(POLICY)
    assert policy.regression == pytest.approx(0.10)
    assert policy.noise_floor_ms == pytest.approx(20.0)
    # The noise floor decides for a short budget, the regression for a long one.
    assert policy.limit(62.0) == pytest.approx(82.0)
    assert policy.limit(350.0) == pytest.approx(385.0)


def test_the_recorded_budgets_cover_native_and_wasi_on_both_workspaces() -> None:
    runs, scenarios = cold.load_budgets(BUDGETS)
    assert runs >= 5
    assert {s.id for s in scenarios} == {"native_small", "native_large", "wasi_small", "wasi_large"}


def test_a_p50_within_the_headroom_passes_and_one_past_it_fails(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, ("a", 100.0), ("b", 100.0))
    reports = tmp_path / "reports"
    _report(reports, "a", 119.9)  # within max(10 ms, 20 ms)
    _report(reports, "b", 120.1)
    rows, failures = cold.check(budgets, reports, POLICY)
    assert [row.failure is None for row in rows] == [True, False]
    assert len(failures) == 1
    assert failures[0].startswith("b: p50 120.1 ms is over the budget 100 ms")


@pytest.mark.parametrize(
    ("p50", "runs", "failed", "expected"),
    [
        (50.0, 10, 2, "2 run(s) failed"),
        (50.0, 5, 0, "5 run(s), the budgets are for 10"),
        (None, 10, 0, "the report has no start_to_first_diag_ms p50"),
    ],
)
def test_a_report_that_cannot_be_trusted_fails(
    tmp_path: Path, p50: float | None, runs: int, failed: int, expected: str
) -> None:
    budgets = _budgets(tmp_path, ("a", 100.0))
    reports = tmp_path / "reports"
    _report(reports, "a", p50, runs=runs, failed=failed)
    _, failures = cold.check(budgets, reports, POLICY)
    assert failures == [f"a: {expected}"]


def test_a_missing_report_and_an_unbudgeted_one_fail(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, ("a", 100.0))
    reports = tmp_path / "reports"
    _report(reports, "stray", 10.0)
    rows, failures = cold.check(budgets, reports, POLICY)
    assert rows == []
    assert failures[0].startswith("a: no report")
    assert failures[1].startswith("stray: a report no [[scenario]] budgets")


def test_main_exits_0_1_2_and_appends_the_summary(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, ("a", 100.0))
    reports = tmp_path / "reports"
    summary = tmp_path / "summary.md"
    _report(reports, "a", 90.0)
    assert cold.main([str(budgets), str(reports), "--summary", str(summary)]) == 0
    assert "| a | 90.0 ms | 100 ms | 120.0 ms | ok |" in summary.read_text(encoding="utf-8")
    _report(reports, "a", 200.0)
    assert cold.main([str(budgets), str(reports)]) == 1
    assert cold.main([str(budgets), str(tmp_path / "nowhere")]) == 2
    (tmp_path / "bad.toml").write_text("schema_version = 2\nruns = 10\n", encoding="utf-8")
    assert cold.main([str(tmp_path / "bad.toml"), str(reports)]) == 2
