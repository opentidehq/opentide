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

NIGHTLY = "needs.changes.outputs.mode == 'nightly'"

#: The jobs that may hold each write permission (workflow, job). Every other
#: permission is read, at the workflow or the job.
WRITES = {
    ("ci.yml", "python"): {"checks", "code-quality"},  # test report, coverage upload
    ("ci.yml", "nightly-report"): {"issues"},
    ("codeql.yml", None): {"security-events"},
    ("mutants.yml", "issues"): {"issues"},
    ("rust-audit.yml", "issue"): {"issues"},
    ("vocab-upstream.yml", None): {"contents", "pull-requests"},  # opens its PR
    ("publish.yml", "internal-release"): {"contents"},
    ("publish.yml", "release"): {"contents"},
    ("publish.yml", "attest"): {"id-token", "attestations"},
    ("publish.yml", "pypi"): {"id-token"},
    ("publish.yml", "crates"): {"id-token"},
    ("publish.yml", "npm"): {"id-token"},
}

#: The Python oracle's byte-level comparisons run by hand only.
ORACLE = re.compile(
    r"xtask (?:golden|compare|mcp)\b|xtask corpus (?!generate\b)|--oracle\b|--check-determinism|"
    r"golden (?:check|record|diff)\b|--runner (?:node|wasi)\b"
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
    return str(job.get("if", "")).strip() == NIGHTLY


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


def test_the_required_checks_are_the_gate() -> None:
    guide = (ROOT / ".github" / "AGENTS.md").read_text(encoding="utf-8")
    block = guide.split("<!-- required-checks -->", 1)[1].split("```text\n", 1)[1]
    assert block.split("```", 1)[0].split("\n")[:-1] == ["PR gate"]


def test_every_changes_output_a_job_reads_exists() -> None:
    """A typo in `needs.changes.outputs.<x>` reads as empty: the job never runs."""
    text = CI.read_text(encoding="utf-8")
    outputs = set(ci_jobs()["changes"]["outputs"])
    assert set(re.findall(r"needs\.changes\.outputs\.([\w-]+)", text)) <= outputs


def test_the_changes_job_exports_what_changes_py_writes() -> None:
    from tests.test_ci.test_changes import changes, metadata

    dirs, _ = changes.workspace_graph(metadata())
    written = set(changes.Plan(mode="pr").outputs(dirs))
    assert set(ci_jobs()["changes"]["outputs"]) == written


def test_the_pr_gates_jobs_run_on_linux() -> None:
    for job_id, job in ci_jobs().items():
        release_or_nightly = "release" in str(job.get("if", "")) or nightly_only(job)
        if not release_or_nightly and "runs-on" in job:
            assert job["runs-on"] == "ubuntu-latest", job_id


def test_only_the_build_compiles_the_gates_workspace() -> None:
    """One build: the Rust tests run its archive, the Python jobs its extension."""
    compiles = re.compile(r"\bcargo (?:build|test|nextest run)\b|\buv sync\b(?!.*--no-install)")
    for job_id in ("rust-tests", "python", "gitlab-ci-lint", "lint"):
        job = ci_jobs()[job_id]
        prebuilt = "OPENTIDE_ENGINE_PREBUILT" in (job.get("env") or {})
        for step in job["steps"]:
            for line in str(step.get("run", "")).replace("\\\n", " ").splitlines():
                if compiles.search(line):
                    reuses = "--binaries-metadata" in step["run"] or "--archive-file" in line
                    assert reuses or (prebuilt and "uv sync" in line), (job_id, line)


# --- What no workflow does ---------------------------------------------------


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_no_workflow_runs_a_python_oracle_comparison(path: Path) -> None:
    for job_id, run in runs(path):
        assert not ORACLE.search(run), (path.name, job_id, run)


def test_the_oracle_workflows_and_the_full_ci_label_are_gone() -> None:
    for name in ("golden.yml", "golden-preview.yml", "docs.yml", "stack-comment.yml"):
        assert not (WORKFLOWS / name).exists(), name
    for path in ALL:
        assert "full-ci" not in path.read_text(encoding="utf-8"), path.name


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_actions_are_pinned_by_commit(path: Path) -> None:
    for job in load(path)["jobs"].values():
        uses = [job["uses"]] if "uses" in job else []
        uses += [s["uses"] for s in job.get("steps") or [] if "uses" in s]
        for action in uses:
            assert action.startswith("./") or re.fullmatch(
                r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", action
            ), (path.name, action)


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_permissions_are_least_privilege(path: Path) -> None:
    workflow = load(path)
    top = workflow.get("permissions")
    assert isinstance(top, dict), f"{path.name}: no workflow-level permissions"
    for job_id, job in [(None, {"permissions": top}), *workflow["jobs"].items()]:
        granted = job.get("permissions") or {}
        writes = {scope for scope, level in granted.items() if level == "write"}
        assert writes <= WRITES.get((path.name, job_id), set()), (path.name, job_id, writes)


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_checkouts_keep_no_credentials(path: Path) -> None:
    if path.name == "vocab-upstream.yml":
        pytest.skip("pushes the branch of the pull request it opens")
    for job in load(path)["jobs"].values():
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


def test_the_nightly_is_one_workflow() -> None:
    """The workflows ci.yml's nightly calls have no schedule of their own."""
    called = {
        job["uses"].removeprefix("./.github/workflows/")
        for job in ci_jobs().values()
        if str(job.get("uses", "")).startswith("./")
    }
    assert {"coverage.yml", "bench.yml", "oracle.yml", "schema.yml"} <= called
    for name in called:
        assert set(triggers(load(WORKFLOWS / name))) <= {"workflow_call", "workflow_dispatch"}


def test_no_workflow_runs_on_a_tag() -> None:
    for path in ALL:
        push = triggers(load(path)).get("push") or {}
        assert "tags" not in push, path.name


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


def test_publish_mints_oidc_tokens_in_its_publish_jobs_only() -> None:
    holders = {
        job_id
        for job_id, job in load(PUBLISH)["jobs"].items()
        if (job.get("permissions") or {}).get("id-token") == "write"
    }
    assert holders == {"attest", "pypi", "crates", "npm"}
    assert load(PUBLISH)["permissions"] == {"contents": "read"}


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
