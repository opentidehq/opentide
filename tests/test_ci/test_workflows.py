"""The CI invariants that catch real mistakes (.github/AGENTS.md).

actionlint (in `lint`) checks the workflows' syntax, expressions and shell;
these tests hold what it cannot: the one required check sees every job, no
workflow runs the Python oracle's comparisons, actions are pinned, permissions
are least-privilege, runs are grouped, and only the release train publishes,
with an internal channel that reaches no registry.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from tests.test_ci import publish_commands

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
PUBLISH = WORKFLOWS / "publish.yml"
ALL = sorted(WORKFLOWS.glob("*.yml"))
COMPOSITES = sorted((ROOT / ".github" / "actions").glob("*/action.yml"))

NIGHTLY = "needs.changes.outputs.mode == 'nightly'"

#: The jobs that may hold each write permission (workflow, job). Every other
#: permission is read, at the workflow or the job.
WRITES = {
    ("ci.yml", "python"): {"checks", "code-quality"},  # test report, coverage upload
    ("ci.yml", "nightly-report"): {"issues"},
    ("codeql.yml", None): {"security-events"},
    ("rust-audit.yml", "issue"): {"issues"},
    ("vocab-upstream.yml", None): {"contents", "pull-requests"},  # opens its PR
    ("publish.yml", "internal-release"): {"contents"},
    ("publish.yml", "release"): {"contents"},
    ("publish.yml", "attest"): {"id-token", "attestations"},
    ("publish.yml", "pypi"): {"id-token"},
    ("publish.yml", "crates"): {"id-token"},
    ("publish.yml", "npm"): {"id-token"},
}

#: The Python oracle's byte-level comparisons run by hand only. `corpus
#: generate` and `corpus faults --out` write workspaces and run no oracle.
ORACLE = re.compile(
    r"xtask (?:golden|compare|mcp)\b|xtask corpus (?!generate\b|faults --out\b)|--oracle\b|"
    r"--check-determinism|golden (?:check|record|diff)\b|--runner (?:node|wasi)\b"
)


def load(path: Path) -> dict[Any, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    """The workflow's `on` (PyYAML reads the key `on` as True)."""
    on = workflow.get("on", workflow.get(True))
    return {on: None} if isinstance(on, str) else dict(on)


def runs(path: Path) -> list[tuple[str, str]]:
    return [
        (job_id, str(step.get("run", "")))
        for job_id, job in load(path)["jobs"].items()
        for step in job.get("steps") or []
    ]


def ci_jobs() -> dict[str, Any]:
    return load(CI)["jobs"]


def nightly_only(job: dict[str, Any]) -> bool:
    """The nightly's, whether or not it runs after a failed need (`always() && …`)."""
    return str(job.get("if", "")).strip() in {NIGHTLY, f"always() && {NIGHTLY}"}


# --- The one required check ------------------------------------------------


def test_the_gate_needs_every_job_that_is_not_the_nightlys() -> None:
    jobs = ci_jobs()
    gated = set(jobs["gate"]["needs"])
    expected = {
        job_id
        for job_id, job in jobs.items()
        if job_id not in {"gate", "nightly-report"} and not nightly_only(job)
    }
    assert gated == expected, {"missing": expected - gated, "extra": gated - expected}
    assert jobs["gate"]["name"] == "PR gate"
    assert jobs["gate"]["if"] == "always()"
    # The branch rules require it alone; the guide lists what they require.
    guide = (ROOT / ".github" / "AGENTS.md").read_text(encoding="utf-8")
    block = guide.split("<!-- required-checks -->", 1)[1].split("```text\n", 1)[1]
    assert block.split("```", 1)[0].split("\n")[:-1] == ["PR gate"]


@pytest.mark.parametrize(
    ("results", "passes"),
    [
        ({"changes": "success", "build": "success", "node": "skipped"}, True),
        ({"changes": "success", "build": "failure"}, False),
        ({"changes": "success", "build": "cancelled"}, False),
        ({"changes": "failure", "build": "skipped"}, False),
    ],
)
def test_the_gate_fails_unless_every_needed_job_passed(
    results: dict[str, str], passes: bool
) -> None:
    script = ci_jobs()["gate"]["steps"][0]["run"]
    body = script.split("<<'PY'\n", 1)[1].rsplit("PY", 1)[0]
    needs = {job: {"result": result} for job, result in results.items()}
    done = subprocess.run(
        ["python3", "-c", body.replace("\n          ", "\n").strip()],
        env={"NEEDS": json.dumps(needs), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (done.returncode == 0) is passes, done.stdout + done.stderr


def test_the_changes_jobs_outputs_are_what_changes_py_writes() -> None:
    """Each output is changes.py's own, read under its own name, and every one a job
    reads exists: a typo in `needs.changes.outputs.<x>` or a swapped mapping
    (`vocab: ${{ steps.plan.outputs.fields }}`) reads as empty or valid, and the job
    never runs."""
    from tests.test_ci.test_changes import changes, metadata

    outputs = ci_jobs()["changes"]["outputs"]
    dirs, _ = changes.workspace_graph(metadata())
    assert set(outputs) == set(changes.Plan(mode="pr").outputs(dirs))
    for name, value in outputs.items():
        assert value == f"${{{{ steps.plan.outputs.{name} }}}}", name
    read = set(re.findall(r"needs\.changes\.outputs\.([\w-]+)", CI.read_text(encoding="utf-8")))
    assert read <= set(outputs)


#: Gate jobs pinned to one Linux image: `throughput`'s instruction budgets
#: (tests/bench/instructions.toml) are recorded under one valgrind and glibc, so
#: they are checked on that image, as bench.yml's timings are on theirs.
PINNED_RUNNERS = {"throughput": "ubuntu-24.04"}


def test_the_gates_jobs_run_on_linux_and_only_the_build_compiles() -> None:
    """A pull request's jobs run on Linux; `build` builds and runs the Rust tests and
    `native` builds the wheel the Python jobs install: no other job compiles again."""
    for job_id, job in ci_jobs().items():
        release_or_nightly = "release" in str(job.get("if", "")) or nightly_only(job)
        if not release_or_nightly and "runs-on" in job:
            assert job["runs-on"] == PINNED_RUNNERS.get(job_id, "ubuntu-latest"), job_id
    compiles = re.compile(
        r"\bcargo (?:build|test|nextest run)\b|\bmaturin\b|\buv (?:sync|build)\b(?!.*--no-install)"
    )
    for job_id in ("python", "gitlab-ci-lint", "lint"):
        job = ci_jobs()[job_id]
        env = job.get("env") or {}
        for step in job["steps"]:
            run = str(step.get("run", ""))
            for line in run.replace("\\\n", " ").splitlines():
                assert not compiles.search(line), (job_id, line)
        runs = "\n".join(str(step.get("run", "")) for step in job["steps"])
        if job_id in ("python", "gitlab-ci-lint"):
            # The build's wheel, and `uv run` never builds the project again.
            assert "uv pip install --no-deps .native/opentide-*.whl" in runs, job_id
            assert env.get("UV_NO_SYNC") == "1", job_id
            # The wheel E2E tests install that wheel instead of building one.
            assert env.get("OPENTIDE_TEST_WHEELHOUSE") == "${{ github.workspace }}/.native"
    native = "\n".join(str(step.get("run", "")) for step in ci_jobs()["native"]["steps"])
    assert "maturin build --locked --profile dev" in native


# --- What no workflow does ---------------------------------------------------


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_no_workflow_runs_a_python_oracle_comparison(path: Path) -> None:
    for job_id, run in runs(path):
        assert not ORACLE.search(run), (path.name, job_id, run)


@pytest.mark.parametrize("path", ALL + COMPOSITES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_actions_are_pinned_by_commit_and_local_ones_exist(path: Path) -> None:
    """A local action's typo fails only when its step runs (actionlint does not see it)."""
    document = load(path)
    jobs = document["jobs"].values() if "jobs" in document else [document["runs"]]
    for job in jobs:
        uses = [job["uses"]] if "uses" in job else []
        uses += [s["uses"] for s in job.get("steps") or [] if "uses" in s]
        for action in uses:
            if action.startswith("./.github/actions/"):
                assert (ROOT / action / "action.yml").is_file(), (path.name, action)
            elif action.startswith("./.github/workflows/"):
                assert (ROOT / action).is_file(), (path.name, action)
            else:
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", action), (path.name, action)


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_permissions_are_least_privilege_and_checkouts_keep_no_credentials(path: Path) -> None:
    """Writes only where WRITES grants them (publish.yml's OIDC tokens in its four
    publishing jobs alone); no checkout leaves the token in .git/config, except
    vocab-upstream.yml's, which pushes the branch of the pull request it opens."""
    workflow = load(path)
    top = workflow.get("permissions")
    assert isinstance(top, dict), f"{path.name}: no workflow-level permissions"
    for job_id, job in [(None, {"permissions": top}), *workflow["jobs"].items()]:
        granted = job.get("permissions") or {}
        writes = {scope for scope, level in granted.items() if level == "write"}
        assert writes <= WRITES.get((path.name, job_id), set()), (path.name, job_id, writes)
    if path.name == "publish.yml":
        # Its publishing jobs do hold their OIDC token: without it, a release fails
        # only on the day it runs.
        holders = {
            job_id
            for job_id, job in workflow["jobs"].items()
            if (job.get("permissions") or {}).get("id-token") == "write"
        }
        assert holders == {"attest", "pypi", "crates", "npm"}
        assert top == {"contents": "read"}
    if path.name == "vocab-upstream.yml":
        return
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert (step.get("with") or {}).get("persist-credentials") is False, path.name


def test_runs_are_grouped_and_a_pull_request_cancels_its_stale_run() -> None:
    for name in ("ci.yml", "codeql.yml"):
        group = load(WORKFLOWS / name)["concurrency"]
        assert group["group"].endswith(
            "${{ github.event_name == 'pull_request' && github.ref || github.run_id }}"
        ), name
        assert group["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"
    publish = load(PUBLISH)["concurrency"]
    assert publish == {"group": "publish", "cancel-in-progress": False}


def called_workflows(name: str) -> set[str]:
    """Every workflow `name` calls, and those they call in turn."""
    called: set[str] = set()
    for job in load(WORKFLOWS / name)["jobs"].values():
        uses = str(job.get("uses", ""))
        if uses.startswith("./.github/workflows/"):
            callee = uses.removeprefix("./.github/workflows/")
            called |= {callee, *called_workflows(callee)}
    return called


def test_the_nightly_is_one_workflow() -> None:
    """What ci.yml's nightly calls, nightly.yml and below, has no schedule of its own:
    a failure there is the nightly's, which `nightly-report` files."""
    called = called_workflows("ci.yml")
    assert {"nightly.yml", "coverage.yml", "bench.yml", "oracle.yml", "engine-fuzz.yml"} <= called
    for name in called:
        assert set(triggers(load(WORKFLOWS / name))) <= {"workflow_call", "workflow_dispatch"}
    jobs = ci_jobs()
    assert jobs["nightly"]["uses"] == "./.github/workflows/nightly.yml"
    assert nightly_only(jobs["nightly"])
    # nightly-report reads the run's failed jobs: one still running when it starts
    # is missed, so it waits for every nightly job and the gate.
    nightly = {job_id for job_id, job in jobs.items() if nightly_only(job)} - {"nightly-report"}
    assert nightly | {"gate"} <= set(jobs["nightly-report"]["needs"])


def test_the_fuzz_matrix_holds_every_target() -> None:
    targets = {path.stem for path in (ROOT / "fuzz" / "fuzz_targets").glob("*.rs")}
    matrix = load(WORKFLOWS / "engine-fuzz.yml")["jobs"]["fuzz"]["strategy"]["matrix"]["target"]
    assert sorted(matrix) == sorted(targets)


# --- Publishing ---------------------------------------------------------------


def test_only_the_release_train_publishes() -> None:
    seen = 0
    for path in ALL:
        if path.name == "publish.yml":
            continue
        for job_id, run in runs(path):
            for command in publish_commands.publishes(run):
                seen += 1
                assert publish_commands.is_dry_run(command), (path.name, job_id, command)
    assert seen, "the dry run's publishes are found: the parser reads the commands"
    assert set(triggers(load(PUBLISH))) == {"workflow_dispatch", "repository_dispatch"}
    # A pushed tag starts nothing: publish.yml creates the tag it releases.
    for path in ALL:
        assert "tags" not in (triggers(load(path)).get("push") or {}), path.name


def test_the_internal_channel_publishes_to_no_registry() -> None:
    jobs = load(PUBLISH)["jobs"]
    for job_id in (
        "attest",
        "release",
        "verify-assets",
        "pypi",
        "crates",
        "npm",
        "smoke-registries",
    ):
        condition = str(jobs[job_id]["if"])
        assert "'internal'" not in condition and "channel !=" not in condition, job_id
        assert "needs.guard.outputs.channel == 'release'" in condition, job_id
    internal = jobs["internal-release"]
    assert internal["if"] == "needs.guard.outputs.channel == 'internal'"
    assert internal["permissions"] == {"contents": "write"}
    script = "\n".join(str(s.get("run", "")) for s in internal["steps"])
    for flag in ("--draft", "--prerelease", "--latest=false", "--verify-tag"):
        assert flag in script, flag
    assert not re.search(r"\b(?:twine|uv publish|cargo publish|npm publish)\b", script)
