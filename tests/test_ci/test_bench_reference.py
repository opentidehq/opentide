"""scripts/ci/bench_reference.py: the benchmarks' reference (bench.yml).

The benchmarks run in ci.yml's nightly (bench.yml called, its jobs named
``Benchmarks / Benchmarks (<engine>)``) and in bench.yml run alone; the
reference is the newest successful run of either on the base branch, on the
same CPU. gh is a fake that answers from the runs below.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "bench_reference",
    Path(__file__).resolve().parents[2] / "scripts" / "ci" / "bench_reference.py",
)
assert _SPEC is not None and _SPEC.loader is not None
bench_reference: ModuleType = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("bench_reference", bench_reference)
_SPEC.loader.exec_module(bench_reference)

CPU = "AMD EPYC 7763 64-Core Processor"
ENV = {
    "GITHUB_REPOSITORY": "opentidehq/opentide",
    "GITHUB_RUN_ID": "900",
    "BASE_BRANCH": "integration/unified-core",
    "ENGINE": "python",
}


class FakeGh:
    """Answers gh's run list, jobs and run download from a table of runs."""

    def __init__(self, runs: dict[str, dict[str, Any]]) -> None:
        self.runs = runs
        self.downloads: list[str] = []

    def __call__(self, *args: str) -> str:
        if args[:2] == ("run", "list"):
            workflow = args[args.index("--workflow") + 1]
            return json.dumps(
                [
                    {"databaseId": int(run_id), "event": run["event"], "createdAt": run["at"]}
                    for run_id, run in self.runs.items()
                    if run["workflow"] == workflow
                ]
            )
        if args[0] == "api":
            run_id = args[2].split("/runs/")[1].split("/")[0]
            return "\n".join(json.dumps(job) for job in self.runs[run_id]["jobs"])
        if args[:2] == ("run", "download"):
            run_id, target = args[2], Path(args[args.index("--dir") + 1])
            self.downloads.append(run_id)
            cpu = self.runs[run_id].get("cpu")
            if cpu is None:
                raise subprocess.CalledProcessError(1, args)
            target.mkdir(parents=True)
            (target / "bench.json").write_text(
                json.dumps({"host": {"cpu_model": cpu}, "run": run_id}), encoding="utf-8"
            )
            return ""
        raise AssertionError(args)


def ci_nightly(at: str, conclusion: str = "success", cpu: str | None = CPU) -> dict[str, Any]:
    return {
        "workflow": "ci.yml",
        "event": "workflow_dispatch",
        "at": at,
        "cpu": cpu,
        "jobs": [
            {"name": "Changes", "conclusion": "success"},
            {"name": "Benchmarks / Benchmarks (python)", "conclusion": conclusion},
            {"name": "Benchmarks / Benchmarks (rust)", "conclusion": "success"},
        ],
    }


def bench_alone(at: str, conclusion: str = "success", cpu: str | None = CPU) -> dict[str, Any]:
    return {
        "workflow": "bench.yml",
        "event": "workflow_dispatch",
        "at": at,
        "cpu": cpu,
        "jobs": [{"name": "Benchmarks (python)", "conclusion": conclusion}],
    }


def ci_push(at: str) -> dict[str, Any]:
    """A push runs no benchmarks: its called job is skipped."""
    run = ci_nightly(at)
    run["event"] = "push"
    run["jobs"] = [{"name": "Benchmarks", "conclusion": "skipped"}]
    return run


def find(tmp_path: Path, runs: dict[str, dict[str, Any]]) -> tuple[str | None, FakeGh]:
    tmp_path.mkdir(exist_ok=True)
    current = tmp_path / "bench.json"
    current.write_text(json.dumps({"host": {"cpu_model": CPU}}), encoding="utf-8")
    fake = FakeGh(runs)
    found = bench_reference.find_reference(ENV, current, tmp_path / "previous", run_gh=fake)
    if found is not None:
        kept = json.loads((tmp_path / "previous" / "bench.json").read_text(encoding="utf-8"))
        assert kept["run"] == found
    assert not (tmp_path / "previous.candidate").exists()
    return found, fake


def test_the_nightly_called_from_ci_is_a_reference(tmp_path: Path) -> None:
    found, _ = find(tmp_path, {"1": ci_nightly("2026-11-14T01:15:00Z")})
    assert found == "1"


def test_the_newest_of_either_workflow_wins(tmp_path: Path) -> None:
    runs = {
        "1": ci_nightly("2026-11-13T01:15:00Z"),
        "2": bench_alone("2026-11-14T10:00:00Z"),
        "3": ci_push("2026-11-14T12:00:00Z"),
    }
    assert find(tmp_path, runs)[0] == "2"
    runs["4"] = ci_nightly("2026-11-15T01:15:00Z")
    assert find(tmp_path / "again", runs)[0] == "4"


def test_a_failed_job_another_cpu_or_a_lost_artifact_is_never_the_reference(
    tmp_path: Path,
) -> None:
    runs = {
        "1": bench_alone("2026-11-10T00:00:00Z"),
        "2": ci_nightly("2026-11-11T00:00:00Z", conclusion="failure"),
        "3": ci_nightly("2026-11-12T00:00:00Z", cpu="Intel Xeon Platinum 8573C"),
        "4": bench_alone("2026-11-13T00:00:00Z", cpu=None),
    }
    found, fake = find(tmp_path, runs)
    assert found == "1"
    assert fake.downloads == ["4", "3", "1"]


def test_this_run_and_pull_requests_are_never_the_reference(tmp_path: Path) -> None:
    runs = {"900": ci_nightly("2026-11-15T00:00:00Z"), "5": bench_alone("2026-11-14T00:00:00Z")}
    runs["5"]["event"] = "pull_request"
    assert find(tmp_path, runs)[0] is None


@pytest.mark.parametrize(
    ("name", "matches"),
    [
        ("Benchmarks (python)", True),
        ("Benchmarks / Benchmarks (python)", True),
        ("Benchmarks / Benchmarks (rust)", False),
        ("Benchmarks", False),
    ],
)
def test_the_job_names_of_both_workflows(name: str, matches: bool) -> None:
    assert bench_reference.is_bench_job(name, "python") is matches


def test_the_workflows_agree_with_the_names_it_looks_for() -> None:
    """ci.yml's `nightly` job calls nightly.yml's `benchmarks` (`Benchmarks`), which
    calls bench.yml, whose job is `Benchmarks (rust)`: `Nightly / Benchmarks /
    Benchmarks (rust)` in ci.yml's run."""
    import yaml

    workflows = Path(__file__).resolve().parents[2] / ".github" / "workflows"

    def caller(path: str, uses: str) -> dict[str, Any]:
        jobs = yaml.safe_load((workflows / path).read_text(encoding="utf-8"))["jobs"]
        return next(job for job in jobs.values() if job.get("uses") == uses)

    nightly = caller("ci.yml", "./.github/workflows/nightly.yml")
    benchmarks = caller("nightly.yml", "./.github/workflows/bench.yml")
    bench = yaml.safe_load((workflows / "bench.yml").read_text(encoding="utf-8"))
    job = bench["jobs"]["bench"]
    assert job["name"] == "Benchmarks (rust)"
    name = f"{nightly['name']} / {benchmarks['name']} / {job['name']}"
    assert bench_reference.is_bench_job(name, "rust")
    assert "scripts/ci/bench_reference.py" in "\n".join(
        str(step.get("run", "")) for step in job["steps"]
    )
    assert set(bench_reference.WORKFLOWS) == {"ci.yml", "bench.yml"}
