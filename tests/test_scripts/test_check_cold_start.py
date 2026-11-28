"""The language server's cold-start gate (scripts/perf/check_cold_start.py, #1754).

The checker holds each scenario's p50 to its target and to the p50 recorded on the
report's CPU, with the headroom of tests/bench/budgets.toml's [policy], and fails a
scenario that has no report or no reference, a report with failed runs, or a report no
scenario budgets.
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
FAST = "Fast CPU"
SLOW = "Slow CPU"


def _budgets(tmp_path: Path, body: str, runs: int = 10) -> Path:
    path = tmp_path / "budgets.toml"
    path.write_text(f"schema_version = 1\nruns = {runs}\n\n{body}", encoding="utf-8")
    return path


def _report(
    reports: Path,
    sid: str,
    p50: float | None,
    *,
    cpu: str = FAST,
    runs: int = 10,
    failed: int = 0,
) -> None:
    reports.mkdir(exist_ok=True)
    report: dict[str, Any] = {
        "label": sid,
        "runs": runs,
        "failed": failed,
        "machine": {"model": cpu},
        "summary": {"start_to_first_diag_ms": {"p50": p50}},
    }
    (reports / f"{sid}.json").write_text(json.dumps(report), encoding="utf-8")


TARGET_ONLY = '[[scenario]]\nid = "a"\nlabel = "a"\ntarget_ms = 100\n'
WITH_CPUS = f"""
[[scenario]]
id = "a"
label = "a"
target_ms = 300
target_waiver = "#1, slower on the runners"

[[cpu_baseline]]
cpu_model = "{FAST}"
[cpu_baseline.p50_ms]
a = 200.0

[[cpu_baseline]]
cpu_model = "{SLOW}"
[cpu_baseline.p50_ms]
a = 250.0
"""


def test_the_headroom_is_the_benchmarks_policy() -> None:
    policy = cold.load_policy(POLICY)
    assert policy.regression == pytest.approx(0.10)
    assert policy.noise_floor_ms == pytest.approx(20.0)
    assert policy.cross_cpu_regression == pytest.approx(0.20)
    # The noise floor decides for a short budget, the regression for a long one.
    assert policy.limit(62.0) == pytest.approx(82.0)
    assert policy.limit(350.0) == pytest.approx(385.0)
    assert policy.limit(250.0, policy.cross_cpu_regression) == pytest.approx(300.0)


def test_the_recorded_budgets_cover_native_and_wasi_on_both_workspaces() -> None:
    budgets = cold.load_budgets(BUDGETS)
    assert budgets.runs >= 5
    ids = {"native_small", "native_large", "wasi_small", "wasi_large"}
    assert {s.id for s in budgets.scenarios} == ids
    # #1746's figures are the targets; every recorded CPU has a p50 for every scenario.
    targets = {s.id: s.target_ms for s in budgets.scenarios}
    assert targets == {
        "native_small": 62,
        "native_large": 127,
        "wasi_small": 192,
        "wasi_large": 350,
    }
    assert budgets.cpu_baselines
    for p50s in budgets.cpu_baselines.values():
        assert set(p50s) == ids


def test_a_p50_within_the_targets_headroom_passes_and_one_past_it_fails(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, TARGET_ONLY)
    reports = tmp_path / "reports"
    _report(reports, "a", 119.9)  # within max(10 ms, 20 ms)
    rows, failures = cold.check(budgets, reports, POLICY)
    assert failures == []
    assert rows[0].limit_ms == pytest.approx(120.0)
    _report(reports, "a", 120.1)
    _, failures = cold.check(budgets, reports, POLICY)
    assert failures == ["a: p50 120.1 ms is over 120.0 ms (held to target 100 ms)"]


def test_a_report_is_held_to_its_own_cpus_baseline(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, WITH_CPUS)
    reports = tmp_path / "reports"
    # The fast CPU's 200 ms + 10%: 225 ms passes on the slow CPU, not on the fast one.
    _report(reports, "a", 225.0, cpu=FAST)
    _, failures = cold.check(budgets, reports, POLICY)
    assert failures == ["a: p50 225.0 ms is over 220.0 ms (held to 200.0 ms on this CPU)"]
    _report(reports, "a", 225.0, cpu=SLOW)
    _, failures = cold.check(budgets, reports, POLICY)
    assert failures == []


def test_an_unrecorded_cpu_is_held_to_the_slowest_plus_the_cross_cpu_headroom(
    tmp_path: Path,
) -> None:
    budgets = _budgets(tmp_path, WITH_CPUS)
    reports = tmp_path / "reports"
    _report(reports, "a", 300.0, cpu="Another CPU")
    rows, failures = cold.check(budgets, reports, POLICY)
    assert failures == []
    assert rows[0].held_to.startswith("slowest recorded 250.0 ms + 20%")
    _report(reports, "a", 300.1, cpu="Another CPU")
    _, failures = cold.check(budgets, reports, POLICY)
    assert len(failures) == 1


def test_an_unwaived_target_caps_a_slower_cpus_baseline(tmp_path: Path) -> None:
    body = WITH_CPUS.replace('target_waiver = "#1, slower on the runners"\n', "").replace(
        "target_ms = 300", "target_ms = 220"
    )
    budgets = _budgets(tmp_path, body)
    reports = tmp_path / "reports"
    _report(reports, "a", 260.0, cpu=SLOW)  # within 250 ms + 10%, over the target's 242 ms
    _, failures = cold.check(budgets, reports, POLICY)
    assert failures == ["a: p50 260.0 ms is over 242.0 ms (held to target 220 ms)"]


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
    budgets = _budgets(tmp_path, TARGET_ONLY)
    reports = tmp_path / "reports"
    _report(reports, "a", p50, runs=runs, failed=failed)
    _, failures = cold.check(budgets, reports, POLICY)
    assert failures == [f"a: {expected}"]


def test_a_scenario_with_no_reference_fails(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, '[[scenario]]\nid = "a"\nlabel = "a"\n')
    reports = tmp_path / "reports"
    _report(reports, "a", 10.0)
    _, failures = cold.check(budgets, reports, POLICY)
    assert failures == ["a: no target and no CPU baseline applies: add one to the budgets"]


def test_a_missing_report_and_an_unbudgeted_one_fail(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, TARGET_ONLY)
    reports = tmp_path / "reports"
    _report(reports, "stray", 10.0)
    rows, failures = cold.check(budgets, reports, POLICY)
    assert rows == []
    assert failures[0].startswith("a: no report")
    assert failures[1].startswith("stray: a report no [[scenario]] budgets")


@pytest.mark.parametrize(
    "body",
    [
        '[[scenario]]\nid = "a"\nlabel = "a"\ntarget_ms = 100\ntarget_waiver = "no issue"\n',
        '[[scenario]]\nid = "a"\nlabel = "a"\ntarget_waiver = "#1, no target"\n',
        TARGET_ONLY + '[[cpu_baseline]]\ncpu_model = "x"\n[cpu_baseline.p50_ms]\nb = 1.0\n',
        TARGET_ONLY + '[[cpu_baseline]]\ncpu_model = "x"\n[cpu_baseline.p50_ms]\na = -1.0\n',
    ],
)
def test_malformed_budgets_are_a_usage_error(tmp_path: Path, body: str) -> None:
    with pytest.raises(cold.UsageError):
        cold.load_budgets(_budgets(tmp_path, body))


def test_main_exits_0_1_2_and_appends_the_summary(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, TARGET_ONLY)
    reports = tmp_path / "reports"
    summary = tmp_path / "summary.md"
    _report(reports, "a", 90.0)
    assert cold.main([str(budgets), str(reports), "--summary", str(summary)]) == 0
    assert "| a | 90.0 ms | 100 ms | target 100 ms | 120.0 ms | ok |" in summary.read_text(
        encoding="utf-8"
    )
    _report(reports, "a", 200.0)
    assert cold.main([str(budgets), str(reports)]) == 1
    assert cold.main([str(budgets), str(tmp_path / "nowhere")]) == 2
    (tmp_path / "bad.toml").write_text("schema_version = 2\nruns = 10\n", encoding="utf-8")
    assert cold.main([str(tmp_path / "bad.toml"), str(reports)]) == 2
