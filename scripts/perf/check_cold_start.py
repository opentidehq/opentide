#!/usr/bin/env python3
"""Hold the language server's cold start to its budgets (#1754).

The cold start is the time from spawning the server to the first diagnostics of a rule it was
asked to open, as `scripts/perf/lsp-bench.mjs` measures it (`start_to_first_diag_ms`), native
and WASI, on the small and the large workspace (`scripts/perf/make_workspace.py`). Each
scenario's p50 is held to `tests/bench/lsp-cold-start.toml` with the rules of every other
benchmark budget (`tests/bench/budgets.toml`, whose `[policy]` it reads):

- the scenario's `target_ms`, an absolute budget, unless a `target_waiver` names the issue that
  will meet it: more than `regression` (10%) above it fails, when the difference is also above
  `noise_floor_s` (20 ms);
- the p50 recorded on the report's CPU model (`[[cpu_baseline]]`): more than `regression` above
  it fails, with the same noise floor; on a CPU model recorded nowhere, the slowest recorded
  p50 + `cross_cpu_regression` (20%). GitHub's runners of one class come on several CPUs, and
  the slowest is about 1.3 times the fastest here.

    check_cold_start.py BUDGETS REPORT_DIR [--policy tests/bench/budgets.toml] [--summary FILE]

REPORT_DIR holds one `<id>.json` per scenario, the report `lsp-bench.mjs --out` writes. A
scenario with no report or no reference, a report with failed runs or another run count than
the budgets ask for, or a report no scenario names fails too, so that a scenario cannot drop out
of the gate unnoticed.

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
    cross_cpu_regression: float

    def limit(self, reference_ms: float, tolerance: float | None = None) -> float:
        """The highest p50 a reference lets pass."""
        tolerance = self.regression if tolerance is None else tolerance
        return reference_ms + max(reference_ms * tolerance, self.noise_floor_ms)


@dataclass(frozen=True)
class Scenario:
    """One budgeted scenario of `tests/bench/lsp-cold-start.toml`."""

    id: str
    label: str
    target_ms: float | None
    target_waiver: str | None


@dataclass(frozen=True)
class Budgets:
    """`tests/bench/lsp-cold-start.toml`."""

    runs: int
    scenarios: list[Scenario]
    #: CPU model -> scenario id -> the p50 recorded on it.
    cpu_baselines: dict[str, dict[str, float]]


@dataclass(frozen=True)
class Row:
    """One scenario's verdict."""

    scenario: Scenario
    p50_ms: float | None
    limit_ms: float | None
    held_to: str
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
            cross_cpu_regression=float(policy["cross_cpu_regression"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise UsageError(
            f"{path}: [policy] needs regression, noise_floor_s and cross_cpu_regression"
        ) from error


def _positive(path: Path, where: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        raise UsageError(f"{path}: {where} must be a positive number")
    return float(value)


def load_budgets(path: Path) -> Budgets:
    """The run count every report must have, the scenarios and the CPU baselines."""
    data = _read_toml(path)
    if data.get("schema_version") != 1:
        raise UsageError(f"{path}: schema_version must be 1")
    runs = data.get("runs")
    if isinstance(runs, bool) or not isinstance(runs, int) or runs < 1:
        raise UsageError(f"{path}: runs must be a positive integer")
    scenarios: list[Scenario] = []
    for entry in data.get("scenario", []):
        if "id" not in entry or "label" not in entry:
            raise UsageError(f"{path}: each [[scenario]] needs id and label")
        sid = str(entry["id"])
        target = entry.get("target_ms")
        waiver = entry.get("target_waiver")
        if waiver is not None and (target is None or "#" not in str(waiver)):
            raise UsageError(
                f"{path}: {sid}: target_waiver needs the target_ms it waives and an issue (#123)"
            )
        scenario = Scenario(
            id=sid,
            label=str(entry["label"]),
            target_ms=None if target is None else _positive(path, f"{sid}.target_ms", target),
            target_waiver=None if waiver is None else str(waiver),
        )
        if any(s.id == scenario.id for s in scenarios):
            raise UsageError(f"{path}: {scenario.id} is listed twice")
        scenarios.append(scenario)
    if not scenarios:
        raise UsageError(f"{path}: no [[scenario]]")
    known = {s.id for s in scenarios}
    cpu_baselines: dict[str, dict[str, float]] = {}
    for entry in data.get("cpu_baseline", []):
        model = entry.get("cpu_model")
        if not isinstance(model, str) or not model or model in cpu_baselines:
            raise UsageError(f"{path}: each [[cpu_baseline]] needs a cpu_model of its own")
        p50s = entry.get("p50_ms", {})
        unknown = set(p50s) - known
        if unknown:
            raise UsageError(f"{path}: {model}: no [[scenario]] {', '.join(sorted(unknown))}")
        cpu_baselines[model] = {
            sid: _positive(path, f"{model}.p50_ms.{sid}", value) for sid, value in p50s.items()
        }
    return Budgets(runs=runs, scenarios=scenarios, cpu_baselines=cpu_baselines)


def _limits(
    scenario: Scenario, cpu: str, budgets: Budgets, policy: Policy
) -> list[tuple[float, str]]:
    """Each limit that applies to the scenario on this CPU, with what it comes from."""
    limits: list[tuple[float, str]] = []
    if scenario.target_ms is not None and scenario.target_waiver is None:
        limits.append((policy.limit(scenario.target_ms), f"target {scenario.target_ms:.0f} ms"))
    own = budgets.cpu_baselines.get(cpu, {}).get(scenario.id)
    if own is not None:
        limits.append((policy.limit(own), f"{own:.1f} ms on this CPU"))
    else:
        recorded = [
            p50s[scenario.id] for p50s in budgets.cpu_baselines.values() if scenario.id in p50s
        ]
        if recorded:
            slowest = max(recorded)
            limits.append(
                (
                    policy.limit(slowest, policy.cross_cpu_regression),
                    f"slowest recorded {slowest:.1f} ms + {policy.cross_cpu_regression:.0%} "
                    "(an unrecorded CPU)",
                )
            )
    return limits


def check_report(
    scenario: Scenario, report: dict[str, Any], budgets: Budgets, policy: Policy
) -> Row:
    """One scenario's report against its budgets."""
    cpu = str(report.get("machine", {}).get("model") or "unknown CPU")
    limits = _limits(scenario, cpu, budgets, policy)
    limit, held_to = min(limits) if limits else (None, "nothing")
    p50 = report.get("summary", {}).get(METRIC, {}).get("p50")
    failure: str | None = None
    if report.get("failed"):
        failure = f"{report['failed']} run(s) failed"
    elif report.get("runs") != budgets.runs:
        failure = f"{report.get('runs')} run(s), the budgets are for {budgets.runs}"
    elif not isinstance(p50, int | float):
        failure = f"the report has no {METRIC} p50"
    elif limit is None:
        failure = "no target and no CPU baseline applies: add one to the budgets"
    elif p50 > limit:
        failure = f"p50 {p50:.1f} ms is over {limit:.1f} ms (held to {held_to})"
    return Row(
        scenario=scenario,
        p50_ms=float(p50) if isinstance(p50, int | float) else None,
        limit_ms=limit,
        held_to=held_to,
        cpu=cpu,
        failure=failure,
    )


def check(budgets: Path, reports: Path, policy_path: Path) -> tuple[list[Row], list[str]]:
    """Every scenario's verdict, and the failures (one line each)."""
    policy = load_policy(policy_path)
    loaded = load_budgets(budgets)
    rows: list[Row] = []
    failures: list[str] = []
    for scenario in loaded.scenarios:
        path = reports / f"{scenario.id}.json"
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            failures.append(f"{scenario.id}: no report ({path})")
            continue
        except (OSError, json.JSONDecodeError) as error:
            raise UsageError(f"{path}: {error}") from error
        row = check_report(scenario, report, loaded, policy)
        rows.append(row)
        if row.failure:
            failures.append(f"{scenario.id}: {row.failure}")
    known = {s.id for s in loaded.scenarios}
    for path in sorted(reports.glob("*.json")):
        if path.stem not in known:
            failures.append(f"{path.stem}: a report no [[scenario]] budgets ({path})")
    return rows, failures


def summary_markdown(rows: list[Row], failures: list[str]) -> str:
    """The step summary: one row per scenario."""
    lines = [
        "### Language server cold start (start to first diagnostics)",
        "",
        "| Scenario | p50 | Target | Held to | Limit | Verdict |",
        "|---|---:|---:|---|---:|---|",
    ]
    for row in rows:
        p50 = "-" if row.p50_ms is None else f"{row.p50_ms:.1f} ms"
        verdict = "ok" if row.failure is None else f"**FAIL**: {row.failure}"
        target = row.scenario.target_ms
        target_text = "-" if target is None else f"{target:.0f} ms"
        if row.scenario.target_waiver is not None:
            target_text += f" (waived: {row.scenario.target_waiver})"
        limit = "-" if row.limit_ms is None else f"{row.limit_ms:.1f} ms"
        lines.append(
            f"| {row.scenario.label} | {p50} | {target_text} | {row.held_to} "
            f"| {limit} | {verdict} |"
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
