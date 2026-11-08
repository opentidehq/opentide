"""The test-strength workflows: coverage, mutants and parity (UC-X.2, #844).

Two of them write: the weekly mutation run files issues and the parity
workflow commits the dashboard. These tests hold the design that keeps that
safe: read-only by default, a write permission only on the one job that needs
it, only on the trigger it is for, and in a job that runs no repository code.
They also hold the coverage workflow to measuring the PyO3 binding with the
whole Python suite, since only Python calls its functions.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
NAMES = ("coverage.yml", "mutants.yml", "parity.yml")
# The only write permissions these workflows hold: (workflow, job) -> scopes.
WRITERS = {
    ("mutants.yml", "issues"): {"issues": "write"},
    ("parity.yml", "commit"): {"contents": "write"},
}
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
# What would run repository code in a job that holds a write token.
REPOSITORY_CODE = re.compile(r"\b(cargo|uv|python3?|pip|npm|npx|node|bash\s+scripts|make)\b")


def _load(name: str) -> dict[Any, Any]:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML reads the key `on` as the boolean True.
    return workflow.get("on") or workflow.get(True) or {}


@pytest.mark.parametrize("name", NAMES)
def test_the_workflow_is_read_only_except_its_writer(name: str) -> None:
    workflow = _load(name)
    assert workflow["permissions"] == {"contents": "read"}, name
    for job_id, job in workflow["jobs"].items():
        permissions = job.get("permissions")
        assert permissions is not None, f"{name} {job_id}: every job states its permissions"
        expected = WRITERS.get((name, job_id))
        if expected is not None:
            assert permissions == expected, (name, job_id, permissions)
        else:
            assert "write" not in permissions.values(), (name, job_id, permissions)


def test_no_writer_runs_on_a_pull_request() -> None:
    mutants = _load("mutants.yml")
    assert set(_triggers(mutants)) == {"schedule", "workflow_dispatch"}
    assert mutants["jobs"]["issues"]["if"] == "github.event_name == 'schedule'"

    parity = _load("parity.yml")
    condition = parity["jobs"]["commit"]["if"]
    assert condition == (
        "github.event_name == 'push' && (github.ref == 'refs/heads/development' || "
        "github.ref == 'refs/heads/integration/unified-core')"
    )
    assert _triggers(parity)["push"] == {"branches": ["development", "integration/unified-core"]}


@pytest.mark.parametrize(("name", "job_id"), sorted(WRITERS))
def test_a_writer_runs_no_repository_code(name: str, job_id: str) -> None:
    job = _load(name)["jobs"][job_id]
    for step in job["steps"]:
        run = str(step.get("run", ""))
        assert not REPOSITORY_CODE.search(run), (name, job_id, run)
    uses = [str(step.get("uses", "")) for step in job["steps"]]
    if name == "mutants.yml":
        # It reads the report job's artifact and calls gh: no checkout at all.
        assert not any(u.startswith("actions/checkout@") for u in uses), uses


def test_the_parity_commit_never_forces_and_changes_one_file() -> None:
    run = "\n".join(str(s.get("run", "")) for s in _load("parity.yml")["jobs"]["commit"]["steps"])
    assert "--force" not in run and " -f " not in run
    assert "git commit --only docs/internal/parity.md" in run
    # Back to the branch that was pushed, which the job condition limits to two.
    assert 'git push origin "HEAD:$BRANCH"' in run
    env = _load("parity.yml")["jobs"]["commit"]["steps"][-1]["env"]
    assert env["BRANCH"] == "${{ github.ref }}"


@pytest.mark.parametrize("name", NAMES)
def test_actions_are_pinned_and_run_steps_interpolate_nothing(name: str) -> None:
    for job_id, job in _load(name)["jobs"].items():
        for step in job["steps"]:
            if "uses" in step:
                assert PINNED.match(step["uses"]), (name, job_id, step["uses"])
            # Values reach a script through env:, never pasted into it.
            assert "${{" not in str(step.get("run", "")), (name, job_id, step.get("name"))


def test_coverage_measures_the_binding_with_the_whole_python_suite() -> None:
    """opentide-native's functions only Python calls, directly or through
    opentide.analysis and the CLI: a list of test files would miss some."""
    job = _load("coverage.yml")["jobs"]["rust"]
    runs = [str(step.get("run", "")) for step in job["steps"]]
    (script,) = [run for run in runs if "pytest" in run]
    words = shlex.split(script[script.index("pytest") :].replace("\\\n", " "))
    assert words[1] == "tests/", words
    assert words[words.index("-m") + 1] == "not gitlab_ci_lint", words
    assert "OPENTIDE_ENGINE_PROFILE=dev uv sync" in script
    assert script.index("cargo llvm-cov show-env") < script.index("uv sync")


def test_coverage_gates_the_crates_with_the_policy() -> None:
    runs = "\n".join(str(s.get("run", "")) for s in _load("coverage.yml")["jobs"]["rust"]["steps"])
    assert "cargo xtask coverage gate --report target/coverage.json" in runs
    assert "rustup component add llvm-tools-preview" in runs
    policy = (ROOT / "xtask" / "coverage.toml").read_text(encoding="utf-8")
    assert "default_lines = 80" in policy
    for crate in ("opentide-schema", "opentide-workspace", "opentide-compile", "opentide-cli"):
        assert re.search(rf'crate = "{crate}"\nlines = 90\n', policy), crate


def test_the_mutation_run_accepts_survivors_and_fails_on_anything_else() -> None:
    steps = _load("mutants.yml")["jobs"]["mutate"]["steps"]
    (run,) = [str(s["run"]) for s in steps if "cargo mutants" in str(s.get("run", ""))]
    # 2: a mutant survived; 3: one timed out. 4 (the unmutated tree failed) fails.
    assert 'case "$status" in 0|2|3) ;; *) exit "$status" ;; esac' in run
    shards = _load("mutants.yml")["jobs"]["mutate"]["strategy"]["matrix"]["shard"]
    assert shards == list(range(int(_load("mutants.yml")["env"]["SHARDS"])))
