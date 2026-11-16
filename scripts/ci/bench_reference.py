"""Find the benchmarks' reference: the base branch's last result (bench.yml).

The benchmarks run in two workflows: ci.yml's nightly calls nightly.yml (its
`nightly` job), which calls bench.yml (its `benchmarks` job), so the job is
named ``Nightly / Benchmarks / Benchmarks (<engine>)`` and the run and its
artifacts belong to ci.yml; and Run workflow on bench.yml
runs it alone (``Benchmarks (<engine>)``). The reference is the newest run of
either on the base branch whose job for this engine succeeded on this run's
CPU model: GitHub's runners of one class come on several CPU generations, and
a 10% rule across two of them measures the hardware. A job that failed its
check is never the reference, so a regression stays red until it is fixed or
the budgets are re-recorded on purpose.

Usage (bench.yml sets the environment)::

    python scripts/ci/bench_reference.py bench.json previous

Writes ``previous/bench.json`` when a reference is found; exits 0 either way.

Environment: ``GITHUB_REPOSITORY``, ``GITHUB_RUN_ID``, ``BASE_BRANCH``,
``ENGINE``, and ``GH_TOKEN`` for the gh command line.

The standard library only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

#: The workflows whose runs can hold benchmark results.
WORKFLOWS = ("ci.yml", "bench.yml")
#: Runs that measure the branch as it is (never a pull request's).
EVENTS = frozenset({"push", "schedule", "workflow_dispatch"})
#: How many runs of each workflow to look through.
LIMIT = 50

Gh = Callable[..., str]


def gh(*args: str) -> str:
    """Run the gh command line and return its standard output."""
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def candidate_runs(run_gh: Gh, repo: str, branch: str, this_run: str) -> list[str]:
    """The base branch's runs of either workflow, newest first, never this run."""
    runs: list[dict[str, Any]] = []
    for workflow in WORKFLOWS:
        listed = run_gh(
            "run",
            "list",
            "--repo",
            repo,
            "--workflow",
            workflow,
            "--branch",
            branch,
            "--limit",
            str(LIMIT),
            "--json",
            "databaseId,event,createdAt",
        )
        runs += [run for run in json.loads(listed or "[]") if run["event"] in EVENTS]
    runs.sort(key=lambda run: run["createdAt"], reverse=True)
    return [str(run["databaseId"]) for run in runs if str(run["databaseId"]) != this_run]


def is_bench_job(name: str, engine: str) -> bool:
    """bench.yml's job for this engine, run alone or called from another workflow."""
    job = f"Benchmarks ({engine})"
    return name == job or name.endswith(f" / {job}")


def engine_succeeded(jobs: Iterable[Mapping[str, Any]], engine: str) -> bool:
    return any(
        is_bench_job(str(job.get("name", "")), engine) and job.get("conclusion") == "success"
        for job in jobs
    )


def run_jobs(run_gh: Gh, repo: str, run_id: str) -> list[dict[str, Any]]:
    # A nightly has about a hundred jobs: every page, one JSON object per line.
    out = run_gh(
        "api",
        "--paginate",
        f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100",
        "--jq",
        ".jobs[] | {name, conclusion} | @json",
    )
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def cpu_model(path: Path) -> str:
    host = json.loads(path.read_text(encoding="utf-8")).get("host") or {}
    return str(host.get("cpu_model") or "")


def find_reference(
    env: Mapping[str, str], current: Path, previous: Path, run_gh: Gh = gh
) -> str | None:
    """Download the reference into ``previous``; return its run id, or None."""
    repo, engine = env["GITHUB_REPOSITORY"], env["ENGINE"]
    cpu = cpu_model(current)
    candidate = previous.with_name(previous.name + ".candidate")
    for run_id in candidate_runs(run_gh, repo, env["BASE_BRANCH"], env.get("GITHUB_RUN_ID", "")):
        if not engine_succeeded(run_jobs(run_gh, repo, run_id), engine):
            continue
        shutil.rmtree(candidate, ignore_errors=True)
        try:
            run_gh(
                "run",
                "download",
                run_id,
                "--repo",
                repo,
                "--name",
                f"bench-{engine}",
                "--dir",
                str(candidate),
            )
        except subprocess.CalledProcessError:
            print(f"::warning::run {run_id} kept no bench-{engine} artifact (expired?)")
            continue
        if cpu_model(candidate / "bench.json") == cpu:
            shutil.rmtree(previous, ignore_errors=True)
            candidate.rename(previous)
            return run_id
    shutil.rmtree(candidate, ignore_errors=True)
    return None


def main(argv: list[str]) -> int:
    current, previous = Path(argv[1]), Path(argv[2])
    branch = os.environ["BASE_BRANCH"]
    run_id = find_reference(os.environ, current, previous)
    if run_id is None:
        print(
            f"No successful {branch} run on {cpu_model(current)} among the last {LIMIT} "
            f"of {' and '.join(WORKFLOWS)}: checking against the budgets alone."
        )
    else:
        print(f"Last {branch} result on {cpu_model(current)}: run {run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
