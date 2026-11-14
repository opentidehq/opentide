"""Helpers the CI contract tests share: ci.yml's jobs, a step's own shell run
in a throwaway checkout, and scripts/ci/changes.py loaded as a module."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
CHANGES = ROOT / "scripts" / "ci" / "changes.py"

# ---- ci.yml's tiers (test_ci_scope.py holds the workflow to them) ------------

INTEGRATION = "integration/unified-core"


def _out(area: str) -> str:
    return f"needs.changes.outputs.{area} == 'true'"


NIGHTLY = "needs.changes.outputs.mode == 'nightly'"
RELEASE = _out("release")
RELEASE_OR_NIGHTLY = f"{RELEASE} || {NIGHTLY}"

# The PR gate: each job and the `changes` area that runs it.
PR_GATE = {
    "lint": "lint",
    "engine-lint": "rust",
    "build": "build",
    "rust-tests": "rust",
    "python": "python",
    "e2e": "python",
    "gitlab-ci-lint": "gitlab",
    "docs": "docs",
    "facade": "facade",
    "node": "node",
    "wasi": "wasi",
    "grammars": "grammars",
    "textmate": "textmate",
    "deny": "deny",
}
# The `if` of a gate job, where it is more than its area: a release pull
# request validates the docs too.
PR_GATE_IF = {job: _out(area) for job, area in PR_GATE.items()} | {
    "docs": f"{_out('docs')} || {RELEASE}",
}
# The release tier, and its `if` (None: none, skipped with the job it needs).
RELEASE_TIER: dict[str, str | None] = {
    "sdist": RELEASE,
    "smoke-sdist": None,
    "packages": RELEASE_OR_NIGHTLY,
    "smoke-wheel": RELEASE,
    "smoke-npm": RELEASE,
    "engine-release-dry-run": RELEASE_OR_NIGHTLY,
    "smoke-installer": RELEASE,
    "engine-package": RELEASE_OR_NIGHTLY,
    "smoke-cargo": RELEASE,
    "publish-dry-run": RELEASE_OR_NIGHTLY,
}
NIGHTLY_JOBS = {
    "engine-test-os",
    "test-full",
    "e2e-full",
    "coverage",
    "benchmarks",
    "oracle",
    "schema",
    "conformance",
    "engine-wasm",
    "npm-install",
    "elastic-sweep",
    "fuzz-smoke",
    "clients",
    "bench",
    "cli-windows-smoke",
    "engine-release-consumers",
}
OWN = {"changes", "gate", "nightly-report"}


def expected_condition(job_id: str) -> str | None:
    """The `if` ci.yml's job must have (None: none)."""
    if job_id in PR_GATE_IF:
        return PR_GATE_IF[job_id]
    if job_id in RELEASE_TIER:
        return RELEASE_TIER[job_id]
    if job_id in NIGHTLY_JOBS:
        return NIGHTLY
    raise KeyError(job_id)


def load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    """The workflow's `on`, as a mapping (PyYAML reads the key `on` as True)."""
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    return dict(on or {})


def ci_jobs() -> dict[str, Any]:
    return load(CI)["jobs"]


def needs(job: dict[str, Any]) -> list[str]:
    found = job.get("needs") or []
    return [found] if isinstance(found, str) else list(found)


def step(job_id: str, *, step_id: str | None = None, name: str | None = None) -> dict[str, Any]:
    """The one step of ci.yml's *job_id* with that id or name."""
    found = [
        s
        for s in ci_jobs()[job_id]["steps"]
        if (step_id is not None and s.get("id") == step_id)
        or (name is not None and s.get("name") == name)
    ]
    assert len(found) == 1, (job_id, step_id, name, len(found))
    return found[0]


def changes() -> ModuleType:
    """scripts/ci/changes.py, loaded once (it is no package)."""
    name = "ci_changes_under_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, CHANGES)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses look the module up while building Plan.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def merged_checkout(repo: Path, changed: list[str], *, merge: bool = True) -> Path:
    """A repository whose HEAD is a pull request's merge commit (its first
    parent the base, its second the change of *changed*), as a pull request's
    checkout with ``fetch-depth: 2`` is; with ``merge=False``, the change's own
    commit (a push: no second parent)."""
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "base")
    (repo / "README").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "switch", "-q", "-c", "change")
    for path in changed:
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("changed\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "change")
    if merge:
        _git(repo, "switch", "-q", "base")
        (repo / "BASE").write_text("moved on\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "base moves")
        _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "change")
    return repo


def run_step(spec: dict[str, Any], cwd: Path, env: dict[str, str]) -> dict[str, str]:
    """The step's own shell in *cwd* with its `env` (expressions replaced by
    *env*); the outputs it wrote to GITHUB_OUTPUT."""
    output = cwd.parent / f"{cwd.name}.output"
    output.write_text("", encoding="utf-8")
    step_env = {k: str(v) for k, v in (spec.get("env") or {}).items() if "${{" not in str(v)}
    subprocess.run(
        ["bash", "-e", "-c", spec["run"]],
        cwd=cwd,
        env={**os.environ, **step_env, **env, "GITHUB_OUTPUT": str(output)},
        check=True,
        capture_output=True,
    )
    lines = output.read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)
