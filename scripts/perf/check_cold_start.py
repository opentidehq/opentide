#!/usr/bin/env python3
"""Hold the language server's cold start to its budgets (#1754).

The cold start is the time from spawning the server to the first diagnostics of a rule it was
asked to open, as `scripts/perf/lsp-bench.mjs` measures it (`start_to_first_diag_ms`), native
and WASI, on the small and the large workspace (`scripts/perf/make_workspace.py`). Each
scenario's p50 is held to its budget in `tests/bench/lsp-cold-start.toml` with the headroom
every other budget has (`tests/bench/budgets.toml`, `[policy]`): it fails when it is more than
`regression` (10%) above the budget and the difference is also above `noise_floor_s` (20 ms).

    check_cold_start.py BUDGETS REPORT_DIR [--policy tests/bench/budgets.toml] [--summary FILE]

REPORT_DIR holds one `<id>.json` per scenario, the report `lsp-bench.mjs --out` writes. A
scenario with no report, a report with failed runs or fewer runs than the budgets ask for, or a
report no scenario names fails too, so that a scenario cannot drop out of the gate unnoticed.

Exit status: 0 every scenario within its budget, 1 a scenario failed, 2 usage error or an
unreadable file.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10, which opentide's tests also run on
    import tomli as tomllib  # an opentide dependency there

ROOT = Path(__file__).resolve().parents[2]
METRIC = "start_to_first_diag_ms"


@dataclass(frozen=True)
class Policy:
    """The headroom of `tests/bench/budgets.toml`'s `[policy]`."""

    regression: float
    noise_floor_ms: float

    def limit(self, budget_ms: float) -> float:
        """The highest p50 a budget lets pass."""
        return budget_ms + max(budget_ms * self.regression, self.noise_floor_ms)


@dataclass(frozen=True)
class Scenario:
    """One budgeted scenario of `tests/bench/lsp-cold-start.toml`."""

    id: str
    label: str
    budget_ms: float


@dataclass(frozen=True)
class Row:
    """One scenario's verdict."""

    scenario: Scenario
    p50_ms: float | None
    limit_ms: float
    cpu: str
    failure: str | None


class UsageError(Exception):
    """A file is missing, unreadable, or not of the expected shape."""


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise UsageError(f"{path}: {error}") from error


def load_policy(path: Path) -> Policy:
    """`[policy]` of the benchmark budgets: the one headroom rule."""
    policy = _read_toml(path).get("policy", {})
    try:
        return Policy(
            regression=float(policy["regression"]),
            noise_floor_ms=float(policy["noise_floor_s"]) * 1000.0,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise UsageError(f"{path}: [policy] needs regression and noise_floor_s") from error


def load_budgets(path: Path) -> tuple[int, list[Scenario]]:
    """The run count every report must have, and the scenarios."""
    data = _read_toml(path)
    if data.get("schema_version") != 1:
        raise UsageError(f"{path}: schema_version must be 1")
    runs = data.get("runs")
    if not isinstance(runs, int) or runs < 1:
        raise UsageError(f"{path}: runs must be a positive integer")
    scenarios: list[Scenario] = []
    for entry in data.get("scenario", []):
        try:
            scenario = Scenario(
                id=str(entry["id"]), label=str(entry["label"]), budget_ms=float(entry["budget_ms"])
            )
        except (KeyError, TypeError, ValueError) as error:
            raise UsageError(f"{path}: each [[scenario]] needs id, label and budget_ms") from error
        if scenario.budget_ms <= 0:
            raise UsageError(f"{path}: {scenario.id}: budget_ms must be positive")
        if any(s.id == scenario.id for s in scenarios):
            raise UsageError(f"{path}: {scenario.id} is listed twice")
        scenarios.append(scenario)
    if not scenarios:
        raise UsageError(f"{path}: no [[scenario]]")
    return runs, scenarios


def check_report(scenario: Scenario, report: dict[str, Any], runs: int, policy: Policy) -> Row:
    """One scenario's report against its budget."""
    limit = policy.limit(scenario.budget_ms)
    cpu = str(report.get("machine", {}).get("model") or "unknown CPU")
    p50 = report.get("summary", {}).get(METRIC, {}).get("p50")
    failure: str | None = None
    if report.get("failed"):
        failure = f"{report['failed']} run(s) failed"
    elif report.get("runs") != runs:
        failure = f"{report.get('runs')} run(s), the budgets are for {runs}"
    elif not isinstance(p50, int | float):
        failure = f"the report has no {METRIC} p50"
    elif p50 > limit:
        failure = (
            f"p50 {p50:.1f} ms is over the budget {scenario.budget_ms:.0f} ms "
            f"(+{(p50 / scenario.budget_ms - 1) * 100:.0f}%, the limit is {limit:.1f} ms)"
        )
    return Row(
        scenario=scenario,
        p50_ms=float(p50) if isinstance(p50, int | float) else None,
        limit_ms=limit,
        cpu=cpu,
        failure=failure,
    )


def check(budgets: Path, reports: Path, policy_path: Path) -> tuple[list[Row], list[str]]:
    """Every scenario's verdict, and the failures (one line each)."""
    policy = load_policy(policy_path)
    runs, scenarios = load_budgets(budgets)
    rows: list[Row] = []
    failures: list[str] = []
    for scenario in scenarios:
        path = reports / f"{scenario.id}.json"
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            failures.append(f"{scenario.id}: no report ({path})")
            continue
        except (OSError, json.JSONDecodeError) as error:
            raise UsageError(f"{path}: {error}") from error
        row = check_report(scenario, report, runs, policy)
        rows.append(row)
        if row.failure:
            failures.append(f"{scenario.id}: {row.failure}")
    known = {s.id for s in scenarios}
    for path in sorted(reports.glob("*.json")):
        if path.stem not in known:
            failures.append(f"{path.stem}: a report no [[scenario]] budgets ({path})")
    return rows, failures


def summary_markdown(rows: list[Row], failures: list[str]) -> str:
    """The step summary: one row per scenario."""
    lines = [
        "### Language server cold start (start to first diagnostics)",
        "",
        "| Scenario | p50 | Budget | Limit | Verdict |",
        "|---|---:|---:|---:|---|",
    ]
    for row in rows:
        p50 = "-" if row.p50_ms is None else f"{row.p50_ms:.1f} ms"
        verdict = "ok" if row.failure is None else f"**FAIL**: {row.failure}"
        lines.append(
            f"| {row.scenario.label} | {p50} | {row.scenario.budget_ms:.0f} ms "
            f"| {row.limit_ms:.1f} ms | {verdict} |"
        )
    lines.extend(f"- **FAIL**: {failure}" for failure in failures if not _in_rows(failure, rows))
    cpus = sorted({row.cpu for row in rows})
    if cpus:
        lines.extend(["", f"CPU: {', '.join(cpus)}"])
    return "\n".join(lines) + "\n"


def _in_rows(failure: str, rows: list[Row]) -> bool:
    return any(failure.startswith(f"{row.scenario.id}: ") and row.failure for row in rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("budgets", type=Path)
    parser.add_argument("reports", type=Path)
    parser.add_argument("--policy", type=Path, default=ROOT / "tests/bench/budgets.toml")
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.reports.is_dir():
            raise UsageError(f"{args.reports}: not a directory")
        rows, failures = check(args.budgets, args.reports, args.policy)
    except UsageError as error:
        print(f"check_cold_start: {error}", file=sys.stderr)
        return 2
    summary = summary_markdown(rows, failures)
    print(summary, end="")
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(summary)
    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
