"""What runs on a pull request, and what only in the full set.

A pull request runs the core gates: lint, the engine's lint and tests on three
operating systems, Python 3.10 and 3.14, E2E, GitLab CI lint, golden compare,
the corpora, cargo deny and CodeQL. They are the required checks, so their jobs
carry no ``if``: a required check that never starts blocks the merge, and one
skipped by its ``if`` would pass without running.

The full set adds everything else (Python 3.11-3.13, the engine release dry
run, WebAssembly, crate packaging, grammars, the Elastic sweep, fuzz smoke, the
Windows CLI smoke, the facade crate's every feature and semver checks, the
Node package, the cross-SDK conformance suite, LSP clients, benchmarks, the
E2E tests marked ``full_set``, Rust coverage, golden determinism, the docs
check and the publish dry run). It runs nightly, on every push to development
and integration/unified-core, on Run workflow, and on a pull request that
carries the ``full-ci`` label: each such job's
``if`` is exactly ``FULL_SET``. The engine release dry run (and crate
packaging) also runs on a pull request that changes the release's inputs, and
the grammar checks on one that changes the grammars, through ci.yml's
``changes`` job, which fails open.
"""

from __future__ import annotations

import importlib.util
import os
import shlex
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
INTEGRATION = "integration/unified-core"

FULL_SET = (
    "github.event_name != 'pull_request' || "
    "contains(github.event.pull_request.labels.*.name, 'full-ci')"
)


def _paths_condition(output: str) -> str:
    """The `if` of a job that runs in the full set and when `changes` reports
    `output` (or did not succeed: the filter fails open)."""
    return (
        "!cancelled() && (\n"
        "  github.event_name != 'pull_request'\n"
        "  || contains(github.event.pull_request.labels.*.name, 'full-ci')\n"
        "  || needs.changes.result != 'success'\n"
        f"  || needs.changes.outputs.{output} == 'true'\n"
        ")"
    )


# ci.yml's jobs on every pull request: no `if`, and only such jobs needed.
CI_CORE = {
    "changes",
    "lint",
    "engine",
    "engine-test-part",
    "deny",
    "test",
    "cli-e2e",
    "gitlab-ci-lint",
    "golden-compare",
    "corpus-part",
}
# Jobs that gather the parts of a core gate under the required check's name
# (#841): `if` is exactly GATHER, so a failed part fails it instead of
# skipping it (a skipped required check passes), and it fails unless the job
# it needs succeeded.
GATHER = "${{ !cancelled() }}"
CI_GATHER = {"corpus": "corpus-part", "engine-test": "engine-test-part"}
# ci.yml's jobs in the full set only.
CI_FULL = {
    "test-full",
    "engine-wasm",
    "elastic-sweep",
    "fuzz-smoke",
    "clients",
    "bench",
    "cli-windows-smoke",
    "cli-e2e-full",
    "facade",
    "node",
    "conformance",
}
# ci.yml's jobs in the full set and on a pull request that changes their inputs.
CI_PATHS = {
    "engine-release-dry-run": "release",
    "engine-package": "release",
    "grammars": "grammars",
    "textmate": "grammars",
}
# Jobs that run when the job they need does, and only then.
CI_DEPENDENT = {"engine-release-consumers": "engine-release-dry-run"}

# The other workflows' jobs in the full set: (workflow, job).
OTHER_FULL = [
    ("coverage.yml", "rust"),
    ("golden.yml", "determinism"),
    ("docs.yml", "validate"),
    ("publish-dry-run.yml", "crate"),
    ("publish-dry-run.yml", "npm"),
    ("publish-dry-run.yml", "pypi"),
]
# Every workflow with a job in the full set runs it nightly.
NIGHTLY = ["ci.yml", "coverage.yml", "golden.yml", "docs.yml", "publish-dry-run.yml"]


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # PyYAML reads the key `on` as True.
    return dict(workflow.get("on", workflow.get(True)) or {})


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def _golden() -> ModuleType:
    """test_golden_workflow.py's expression evaluator and git helpers."""
    spec = importlib.util.spec_from_file_location(
        "golden_workflow_rules", ROOT / "tests" / "test_ci" / "test_golden_workflow.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_condition(job_id: str) -> str | None:
    """The `if` ci.yml's job must have (None: no `if`)."""
    if job_id in CI_FULL:
        return FULL_SET
    if job_id in CI_PATHS:
        return _paths_condition(CI_PATHS[job_id])
    return None


def _ci_jobs() -> dict[str, Any]:
    return _load(CI)["jobs"]


def test_every_ci_job_has_one_scope() -> None:
    scopes = [CI_CORE, CI_FULL, set(CI_PATHS), set(CI_DEPENDENT), set(CI_GATHER)]
    every = [job for scope in scopes for job in scope]
    assert len(every) == len(set(every)), "a job is in two scopes"
    assert set(_ci_jobs()) == set(every)


@pytest.mark.parametrize("job_id", sorted(CI_CORE))
def test_the_core_gates_run_on_every_pull_request(job_id: str) -> None:
    job = _ci_jobs()[job_id]
    assert "if" not in job, f"{job_id} is a core gate: it runs on every pull request"
    assert "continue-on-error" not in job, job_id
    assert set(_needs(job)) <= CI_CORE, (job_id, _needs(job))


@pytest.mark.parametrize(("job_id", "parts"), sorted(CI_GATHER.items()))
def test_a_gathering_job_fails_unless_every_part_passed(job_id: str, parts: str) -> None:
    job = _ci_jobs()[job_id]
    assert job.get("if") == GATHER, job_id
    assert _needs(job) == [parts], job_id
    assert parts in CI_CORE, f"{parts} runs on every pull request"
    (step,) = job["steps"]
    assert step["env"]["RESULT"] == f"${{{{ needs.{parts}.result }}}}"
    assert 'test "${RESULT}" = success' in step["run"]


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "success"])
def test_the_gathering_check_passes_only_on_success(result: str) -> None:
    """The step's own shell, run on each result a part can have."""
    (step,) = _ci_jobs()["corpus"]["steps"]
    done = subprocess.run(
        ["bash", "-ec", step["run"]],
        env={**os.environ, "RESULT": result},
        capture_output=True,
        check=False,
    )
    assert (done.returncode == 0) is (result == "success"), result


@pytest.mark.parametrize("job_id", sorted(CI_FULL | set(CI_PATHS)))
def test_the_rest_runs_in_the_full_set(job_id: str) -> None:
    job = _ci_jobs()[job_id]
    assert job.get("if") == expected_condition(job_id), job_id
    if job_id in CI_PATHS:
        assert _needs(job) == ["changes"], job_id


@pytest.mark.parametrize(("job_id", "after"), sorted(CI_DEPENDENT.items()))
def test_a_dependent_job_runs_with_the_job_it_needs(job_id: str, after: str) -> None:
    job = _ci_jobs()[job_id]
    # No `if`: the implicit success() skips it whenever `after` is skipped.
    assert "if" not in job, job_id
    assert _needs(job) == [after]


def test_python_runs_oldest_and_newest_on_a_pull_request_and_every_version_in_the_full_set() -> (
    None
):
    jobs = _ci_jobs()
    core = jobs["test"]["strategy"]["matrix"]["python-version"]
    full = jobs["test-full"]["strategy"]["matrix"]["python-version"]
    assert core == ["3.10", "3.14"]
    assert sorted(core + full, key=lambda v: tuple(map(int, v.split(".")))) == [
        "3.10",
        "3.11",
        "3.12",
        "3.13",
        "3.14",
    ]
    # The same tests in every cell: one selection, no coverage outside 3.14.
    marker = '-m "not cli_e2e and not cli_smoke and not gitlab_ci_lint"'
    runs = [str(step.get("run", "")) for step in jobs["test-full"]["steps"]]
    assert [run for run in runs if "pytest" in run] == [
        f"uv run pytest tests/ --no-cov -q -n 4 {marker}"
    ]
    assert jobs["test"]["name"] == jobs["test-full"]["name"]


def test_ci_runs_on_every_pull_request_push_nightly_and_on_demand() -> None:
    workflow = _load(CI)
    triggers = _triggers(workflow)
    assert triggers["pull_request"] is None, "every base branch, no path filter"
    assert {"development", INTEGRATION} <= set(triggers["push"]["branches"])
    assert "workflow_dispatch" in triggers
    assert len(triggers["schedule"]) == 1
    # The nightly run and a push to development must not cancel each other.
    assert "github.event_name" in workflow["concurrency"]["group"]


@pytest.mark.parametrize(("name", "job_id"), OTHER_FULL)
def test_the_other_workflows_full_set_jobs(name: str, job_id: str) -> None:
    workflow = _load(WORKFLOWS / name)
    assert workflow["jobs"][job_id].get("if") == FULL_SET, (name, job_id)
    triggers = _triggers(workflow)
    # No path filter on the trigger: the label must reach the job.
    assert "pull_request" in triggers and not triggers["pull_request"], name
    assert {"development", INTEGRATION} <= set(triggers["push"]["branches"]), name
    assert "workflow_dispatch" in triggers, name


@pytest.mark.parametrize("name", NIGHTLY)
def test_the_full_set_runs_nightly(name: str) -> None:
    workflow = _load(WORKFLOWS / name)
    schedule = _triggers(workflow)["schedule"]
    assert len(schedule) == 1, name
    day, month, weekday = schedule[0]["cron"].split()[2:]
    assert (day, month, weekday) == ("*", "*", "*"), f"{name}: every night"
    group = str((workflow.get("concurrency") or {}).get("group", ""))
    if (workflow.get("concurrency") or {}).get("cancel-in-progress") is True:
        assert "github.event_name" in group, f"{name}: the nightly run cancels a push's"


def test_the_schema_workflow_is_path_filtered_on_pull_requests() -> None:
    triggers = _triggers(_load(WORKFLOWS / "schema.yml"))
    paths = triggers["pull_request"]["paths"]
    # bindings/python: the SDK's core, whose stub `cargo xtask stubs` generates (UC-5.2b).
    for path in (
        "crates/opentide-schema/**",
        "src/opentide/_native/**",
        "bindings/python/**",
        "xtask/src/stubs.rs",
    ):
        assert path in paths, path
    assert {"development", INTEGRATION} <= set(triggers["push"]["branches"])
    assert "schedule" in triggers and "workflow_dispatch" in triggers


def test_the_oracles_run_on_parser_changes_not_every_crate() -> None:
    paths = _triggers(_load(WORKFLOWS / "oracle.yml"))["pull_request"]["paths"]
    assert "crates/**" not in paths
    for path in ("crates/opentide-kql/**", "crates/opentide-analysis/**", "crates/*/Cargo.toml"):
        assert path in paths, path


def _context(event: str, labels: str, result: str, outputs: dict[str, str]) -> dict[str, str]:
    return {
        "github.event_name": event,
        "github.base_ref": "development" if event == "pull_request" else "",
        "needs.changes.result": result,
        "labels": labels,
        **{f"needs.changes.outputs.{key}": value for key, value in outputs.items()},
    }


QUIET = {"release": "false", "grammars": "false"}


@pytest.mark.parametrize(
    ("event", "labels", "result", "outputs", "full", "release", "grammars"),
    [
        # A pull request that changes neither: the core gates only.
        ("pull_request", "", "success", QUIET, False, False, False),
        ("pull_request", "perf", "success", QUIET, False, False, False),
        ("pull_request", "full-ci-later", "success", QUIET, False, False, False),
        # The label runs everything.
        ("pull_request", "full-ci", "success", QUIET, True, True, True),
        ("pull_request", "docs,full-ci", "success", QUIET, True, True, True),
        # A change to the release's inputs, or to the grammars.
        ("pull_request", "", "success", {**QUIET, "release": "true"}, False, True, False),
        ("pull_request", "", "success", {**QUIET, "grammars": "true"}, False, False, True),
        # The filter fails open.
        ("pull_request", "", "failure", {"release": "", "grammars": ""}, False, True, True),
        # Everything else is the full set.
        ("push", "", "success", {"release": "true", "grammars": "true"}, True, True, True),
        ("schedule", "", "success", {"release": "true", "grammars": "true"}, True, True, True),
        ("workflow_dispatch", "", "failure", {"release": "", "grammars": ""}, True, True, True),
    ],
)
def test_when_the_full_set_runs(
    event: str,
    labels: str,
    result: str,
    outputs: dict[str, str],
    full: bool,
    release: bool,
    grammars: bool,
) -> None:
    evaluate = _golden()._evaluate
    jobs = _ci_jobs()
    context = _context(event, labels, result, outputs)
    # A job that needs nothing: the implicit success() holds whatever `changes` did.
    alone = {**context, "needs.changes.result": "success"}
    expected = {"release": release, "grammars": grammars}
    for job_id in sorted(CI_FULL):
        assert not _needs(jobs[job_id]), job_id
        assert evaluate(jobs[job_id]["if"], alone) is full, job_id
    for job_id, output in sorted(CI_PATHS.items()):
        assert evaluate(jobs[job_id]["if"], context) is expected[output], job_id
    for name, job_id in OTHER_FULL:
        job = _load(WORKFLOWS / name)["jobs"][job_id]
        assert not _needs(job), (name, job_id)
        assert evaluate(job["if"], alone) is full, (name, job_id)


def _paths_step() -> dict[str, Any]:
    steps = _ci_jobs()["changes"]["steps"]
    return next(step for step in steps if step.get("id") == "paths")


def test_the_changes_job_reads_the_merge_commit() -> None:
    job = _ci_jobs()["changes"]
    assert job["outputs"] == {
        "release": "${{ steps.paths.outputs.release }}",
        "grammars": "${{ steps.paths.outputs.grammars }}",
    }
    checkout = job["steps"][0]
    assert checkout["with"] == {"fetch-depth": 2, "persist-credentials": False}


def _run_filter(repo: Path, tmp_path: Path, event: str = "pull_request") -> dict[str, str]:
    """Run the `changes` step's script in `repo`; return its outputs."""
    step = _paths_step()
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "EVENT_NAME": event,
        "RELEASE_PATHS": step["env"]["RELEASE_PATHS"],
        "GRAMMARS_PATHS": step["env"]["GRAMMARS_PATHS"],
        "GITHUB_OUTPUT": str(output),
    }
    subprocess.run(
        ["bash", "-c", step["run"]], cwd=repo, env=env, check=True, capture_output=True, text=True
    )
    lines = output.read_text(encoding="utf-8").splitlines()
    outputs = dict(line.partition("=")[::2] for line in lines)
    assert len(outputs) == len(lines) == 2, lines
    return outputs


@pytest.mark.parametrize(
    ("change", "release", "grammars"),
    [
        ({"src/opentide/cli.py": "changed\n"}, "false", "false"),
        ({"crates/opentide-kql/src/lib.rs": "changed\n"}, "false", "false"),
        ({".github/workflows/ci.yml": "name: CI\n"}, "false", "false"),
        # The release's inputs.
        ({".github/workflows/engine-release.yml": "name: R\n"}, "true", "false"),
        ({".github/workflows/engine-release-build.yml": "name: B\n"}, "true", "false"),
        ({"Cargo.toml": "[workspace]\n"}, "false", "false"),
        ({"Cargo.lock": "version = 4\n"}, "false", "false"),
        ({"crates/opentide-kql/Cargo.toml": "[package]\n"}, "false", "false"),
        ({"rust-toolchain.toml": "[toolchain]\n"}, "false", "false"),
        ({"scripts/engine/release.py": "changed\n"}, "true", "false"),
        ({"scripts/engine/release-notes.md": "new\n"}, "true", "false"),
        # The grammars.
        ({"grammars/kql/grammar.js": "changed\n"}, "false", "true"),
        ({"highlights/test/package.json": "{}\n"}, "false", "true"),
        ({"scripts/engine/check-grammars.sh": "changed\n"}, "false", "true"),
        # Near misses.
        ({"scripts/engine/build-wasm.sh": "changed\n"}, "false", "false"),
        ({"docs/Cargo.toml.md": "new\n"}, "false", "false"),
        ({"crates/opentide-kql/grammars.rs": "new\n"}, "false", "false"),
        # Both, and a deletion.
        ({"Cargo.lock": None, "grammars/spl/grammar.js": "changed\n"}, "false", "true"),
    ],
)
def test_the_filter_reads_the_pull_requests_changes(
    tmp_path: Path, change: dict[str, str | None], release: str, grammars: str
) -> None:
    golden = _golden()
    base = {"Cargo.lock": "version = 3\n"}
    repo = _pull_request(golden, tmp_path, base, change)
    assert _run_filter(repo, tmp_path) == {"release": release, "grammars": grammars}


def _pull_request(
    golden: ModuleType, tmp_path: Path, base: dict[str, str], change: dict[str, str | None]
) -> Path:
    """A repository whose HEAD is a pull request's merge commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    golden._git(repo, "init", "-q", "-b", "base")
    for path, content in {"README.md": "base\n", **base}.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(content, encoding="utf-8")
    golden._commit(repo, "base")
    golden._git(repo, "switch", "-q", "-c", "topic")
    for path, content in change.items():
        if content is None:
            golden._git(repo, "rm", "-q", path)
        else:
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(content, encoding="utf-8")
    golden._commit(repo, "topic")
    golden._git(repo, "switch", "-q", "base")
    (repo / "README.md").write_text("base moved on\n", encoding="utf-8")
    golden._commit(repo, "base moved on")
    golden._git(repo, "merge", "-q", "--no-ff", "--no-edit", "topic")
    return repo


def test_the_filter_fails_open(tmp_path: Path) -> None:
    golden = _golden()
    repo = _pull_request(golden, tmp_path, {}, {"src/opentide/cli.py": "changed\n"})
    quiet = {"release": "false", "grammars": "false"}
    everything = {"release": "true", "grammars": "true"}
    assert _run_filter(repo, tmp_path) == quiet
    # Not a pull request: everything runs.
    assert _run_filter(repo, tmp_path, event="schedule") == everything
    # Not a merge commit (no pull request merge ref): everything runs.
    golden._git(repo, "reset", "-q", "--hard", "HEAD^1")
    assert _run_filter(repo, tmp_path) == everything


def _pytest_markers(job_id: str) -> list[str]:
    """The ``-m`` expression of each pytest step of ci.yml's *job_id*."""
    markers = []
    for step in _ci_jobs()[job_id]["steps"]:
        run = str(step.get("run", ""))
        if "pytest" in run:
            words = shlex.split(run.replace("\\\n", " "))
            markers.append(words[words.index("-m") + 1])
    return markers


def test_the_full_set_e2e_tests_run_in_the_full_set_only() -> None:
    """A test marked ``full_set`` (a wheel built per test, UC-4.5c, #835)
    runs in ``cli-e2e-full``, never on every pull request: ``cli-e2e`` leaves
    it out, and the unit matrix leaves out ``cli_e2e``, which it carries."""
    assert _pytest_markers("cli-e2e") == ["(cli_e2e or cli_smoke) and not full_set"]
    assert _pytest_markers("cli-e2e-full") == ["full_set"]
    for job_id in ("test", "test-full"):
        markers = _pytest_markers(job_id)
        assert markers, job_id
        assert all("not cli_e2e" in marker for marker in markers), (job_id, markers)
    here = Path(__file__).resolve()
    marked = [
        path
        for path in sorted((ROOT / "tests").rglob("*.py"))
        if path.resolve() != here and "mark.full_set" in path.read_text(encoding="utf-8")
    ]
    assert marked, "no test is marked full_set: drop the marker and cli-e2e-full"
    for path in marked:
        assert "mark.cli_e2e" in path.read_text(encoding="utf-8"), path
