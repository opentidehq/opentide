"""What runs on a pull request, and what only in the full set.

A pull request runs the core gates: lint, the engine's lint and tests on three
operating systems, Python 3.10 and 3.14, E2E, GitLab CI lint, golden compare,
the corpora, cargo deny and CodeQL. They are the required checks, so their jobs
carry no ``if``: a required check that never starts blocks the merge, and one
skipped by its ``if`` would pass without running.

The full set adds everything else (Python 3.11-3.13, the engine release dry
run, WebAssembly, crate packaging, grammars, the Elastic sweep, fuzz smoke,
the Windows CLI smoke, the facade crate's every feature and semver checks, the
Node package and its install from a local registry, the installable wheels and
npm tarballs (run artifacts), the cross-SDK conformance suite, the query
fault kinds against the Rust engine (``corpus-queries``), LSP clients,
benchmarks, the E2E tests marked ``full_set``, Rust coverage, golden
determinism, the docs check and the publish dry run). It runs nightly, on
every push to development and integration/unified-core, on Run workflow, and
on a pull request that carries the ``full-ci`` label: each such job's ``if``
is exactly ``FULL_SET``. The engine release dry run (and crate packaging) also
runs on a pull request that changes the release's inputs, and the grammar
checks on one that changes the grammars, through ci.yml's ``changes`` job,
which fails open.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
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
    "golden-compare-part",
}
# Jobs that gather the parts of a core gate under the required check's name
# (#841): `if` is exactly GATHER, so a failed part fails it instead of
# skipping it (a skipped required check passes), and it fails unless the job
# it needs succeeded.
GATHER = "${{ !cancelled() }}"
CI_GATHER = {
    "corpus": "corpus-part",
    "engine-test": "engine-test-part",
    "golden-compare": "golden-compare-part",
}
# A gathering job whose parts a pull request may skip (they are path-scoped):
# it also needs `changes`, to know whether they had to run.
CI_GATHER_SCOPED = {"corpus"}
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
    "packages",
    "conformance",
    "corpus-queries",
}
# ci.yml's jobs in the full set and on a pull request that changes their inputs.
CI_PATHS = {
    "engine-release-dry-run": "release",
    "engine-package": "release",
    "grammars": "grammars",
    "textmate": "grammars",
    # The lean pull request set: the corpora, the Node package and the facade
    # run on a pull request only when their inputs change.
    "corpus-part": "corpus",
    "node": "node",
    "npm-install": "node",
    "facade": "facade",
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
    if job_id in CI_GATHER_SCOPED:
        assert _needs(job) == ["changes", parts], job_id
        assert parts in CI_PATHS, f"{parts} runs on a pull request that changes its inputs"
    else:
        assert _needs(job) == [parts], job_id
        assert parts in CI_CORE, f"{parts} runs on every pull request"
    # The last step judges the parts (golden compare downloads their unused
    # ledger entries first, and only when they passed).
    *before, step = job["steps"]
    assert step["env"]["RESULT"] == f"${{{{ needs.{parts}.result }}}}"
    assert 'test "${RESULT}" = success' in step["run"]
    for earlier in before:
        assert earlier.get("if") == f"needs.{parts}.result == 'success'", (job_id, earlier)


@pytest.mark.parametrize("needed", ["true", "false"])
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "success"])
def test_the_gathering_check_passes_only_on_success(result: str, needed: str) -> None:
    """The step's own shell, run on each result a part can have: success when
    the parts had to run, skipped when they did not (a pull request that
    changes none of their inputs), and nothing else."""
    (step,) = _ci_jobs()["corpus"]["steps"]
    done = subprocess.run(
        ["bash", "-ec", step["run"]],
        env={**os.environ, "RESULT": result, "NEEDED": needed},
        capture_output=True,
        check=False,
    )
    passes = result == ("success" if needed == "true" else "skipped")
    assert (done.returncode == 0) is passes, (result, needed)


# Golden compare (#841): three parts by a hash of the case id, and a gather
# that keeps the required check's name and finds the stale ledger entries.
GOLDEN_PARTS = 3


def _golden_check_step() -> dict[str, Any]:
    *_, step = _ci_jobs()["golden-compare"]["steps"]
    return step


def test_golden_compare_runs_every_part_of_the_cases() -> None:
    job = _ci_jobs()["golden-compare-part"]
    assert job["strategy"]["matrix"]["part"] == list(range(1, GOLDEN_PARTS + 1))
    assert job["strategy"]["fail-fast"] is False
    assert _golden_check_step()["env"]["PARTS"] == str(GOLDEN_PARTS)
    (compare,) = [s for s in job["steps"] if "golden check" in str(s.get("run", ""))]
    assert compare["env"]["PART"] == "${{ matrix.part }}"
    words = shlex.split(compare["run"])
    assert words[:6] == ["cargo", "xtask", "golden", "check", "--engine", "rust"]
    # Part K of the same N in every cell: together, every case exactly once
    # (xtask's the_partitions_run_every_case_exactly_once).
    assert words[words.index("--partition") + 1] == f"${{PART}}/{GOLDEN_PARTS}"
    unused = words[words.index("--unused") + 1]
    assert unused == "golden-unused-${PART}.json"
    assert "--filter" not in words, "a part of every case, not a filtered run"
    (upload,) = [s for s in job["steps"] if s.get("name") == "Upload the unused ledger entries"]
    assert upload["with"]["path"] == "golden-unused-${{ matrix.part }}.json"
    assert upload["with"]["if-no-files-found"] == "error"
    assert "continue-on-error" not in upload and "if" not in upload
    (download,) = _ci_jobs()["golden-compare"]["steps"][:-1]
    assert download["with"] == {"pattern": "golden-unused-*", "merge-multiple": True}


def _gather_golden(tmp_path: Path, result: str, parts: dict[int, list[int]]) -> bool:
    """The gather's own shell, over the unused entries each part wrote."""
    for part, entries in parts.items():
        listed = [
            {"entry": e, "command": "info", "case": "info/*", "target": "stdout", "rule": "r"}
            for e in entries
        ]
        (tmp_path / f"golden-unused-{part}.json").write_text(json.dumps(listed), encoding="utf-8")
    step = _golden_check_step()
    done = subprocess.run(
        ["bash", "-ec", step["run"]],
        cwd=tmp_path,
        env={**os.environ, "RESULT": result, "PARTS": step["env"]["PARTS"]},
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode == 0


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped"])
def test_the_golden_gather_fails_when_a_part_fails(tmp_path: Path, result: str) -> None:
    every: dict[int, list[int]] = {part: [] for part in range(1, GOLDEN_PARTS + 1)}
    assert not _gather_golden(tmp_path, result, every)
    assert _gather_golden(tmp_path, "success", every)


def test_the_golden_gather_fails_without_every_parts_entries(tmp_path: Path) -> None:
    assert not _gather_golden(tmp_path, "success", {1: [], 2: []})


def test_the_golden_gather_fails_on_an_entry_no_part_applied(tmp_path: Path) -> None:
    # Entry 4 applied in part 2 only, entry 7 in none: 7 is stale.
    assert not _gather_golden(tmp_path, "success", {1: [4, 7], 2: [7], 3: [4, 7]})
    # Each entry applied in a part at least: none is stale.
    assert _gather_golden(tmp_path, "success", {1: [4, 7], 2: [7], 3: [4]})


@pytest.mark.parametrize(
    ("event", "labels", "result", "corpus", "needed"),
    [
        ("pull_request", "", "success", "false", False),
        ("pull_request", "", "success", "true", True),
        ("pull_request", "full-ci", "success", "false", True),
        ("pull_request", "", "failure", "", True),
        ("push", "", "success", "false", True),
        ("schedule", "", "success", "false", True),
    ],
)
def test_the_corpus_check_knows_when_its_parts_had_to_run(
    event: str, labels: str, result: str, corpus: str, needed: bool
) -> None:
    """NEEDED is the parts' own condition, without its `!cancelled()`."""
    (step,) = _ci_jobs()["corpus"]["steps"]
    expression = str(step["env"]["NEEDED"]).strip()
    assert expression.startswith("${{") and expression.endswith("}}")
    context = _context(event, labels, result, {"corpus": corpus})
    evaluate = _golden()._evaluate
    assert evaluate(f"always() && ({expression[3:-2].strip()})", context) is needed
    parts = _ci_jobs()["corpus-part"]["if"]
    assert evaluate(parts, context) is needed


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


# The comparisons with the oracle and its recordings that gate CI: (job, the
# matrix part that runs the step or None, the command). The fast ones are core
# gates; the query fault kinds (about eight minutes) run in the full set.
COMPARISONS = [
    ("engine", None, "target/debug/xtask cassettes check"),
    ("corpus-part", "faults", "cargo xtask corpus faults --check --engine rust --only platforms"),
    (
        "corpus-part",
        "faults",
        "cargo xtask corpus faults --check --engine rust --only configuration",
    ),
    ("corpus-part", "diffs", "cargo xtask config diff --against python"),
    ("corpus-queries", None, "cargo xtask corpus faults --check --engine rust --only queries"),
]


@pytest.mark.parametrize(("job_id", "part", "command"), COMPARISONS)
def test_each_comparison_runs_in_its_scope(job_id: str, part: str | None, command: str) -> None:
    job = _ci_jobs()[job_id]
    steps = [step for step in job["steps"] if str(step.get("run", "")).strip() == command]
    assert len(steps) == 1, f"{job_id} runs `{command}` once"
    (step,) = steps
    if part is None:
        assert "if" not in step, f"{job_id}: `{command}` runs whenever the job does"
    else:
        assert step.get("if") == f"matrix.part == '{part}'", (job_id, command)
        assert part in job["strategy"]["matrix"]["part"], part
    # The engine's on every pull request; the corpora's on one that changes
    # their inputs (and in the full set); the query fault kinds in the full set.
    scope = {"engine": CI_CORE, "corpus-part": set(CI_PATHS), "corpus-queries": CI_FULL}
    assert job_id in scope[job_id], job_id


def test_the_query_fault_kinds_read_the_oracle_and_the_corpus_caches() -> None:
    jobs = _ci_jobs()
    job, corpus = jobs["corpus-queries"], jobs["corpus-part"]
    runs = "\n".join(str(step.get("run", "")) for step in job["steps"])
    assert "oracle-requirements.txt" in runs and "OPENTIDE_ORACLE=" in runs
    for name in ("RUSTFLAGS", "CARGO_INCREMENTAL", "RUSTC_WRAPPER", "SCCACHE_DIR"):
        assert job["env"][name] == corpus["env"][name], name


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


# The outputs of ci.yml's `changes` job, one per path-scoped input.
OUTPUTS = ("release", "grammars", "corpus", "node", "facade")
QUIET = dict.fromkeys(OUTPUTS, "false")
EVERYTHING = dict.fromkeys(OUTPUTS, "true")
FAILED = dict.fromkeys(OUTPUTS, "")


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
        ("pull_request", "", "failure", FAILED, False, True, True),
        # The corpora, the Node package and the facade, each on its own input.
        ("pull_request", "", "success", {**QUIET, "corpus": "true"}, False, False, False),
        ("pull_request", "", "success", {**QUIET, "node": "true"}, False, False, False),
        ("pull_request", "", "success", {**QUIET, "facade": "true"}, False, False, False),
        # Everything else is the full set.
        ("push", "", "success", EVERYTHING, True, True, True),
        ("schedule", "", "success", EVERYTHING, True, True, True),
        ("workflow_dispatch", "", "failure", FAILED, True, True, True),
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
    # Each path-scoped job: the full set, its input changed, or the filter failed.
    expected = {
        output: full
        or event != "pull_request"
        or result != "success"
        or outputs.get(output) == "true"
        for output in OUTPUTS
    }
    assert (expected["release"], expected["grammars"]) == (release, grammars)
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
        output: f"${{{{ steps.paths.outputs.{output} }}}}" for output in OUTPUTS
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
        **{f"{output.upper()}_PATHS": step["env"][f"{output.upper()}_PATHS"] for output in OUTPUTS},
        "GITHUB_OUTPUT": str(output),
    }
    subprocess.run(
        ["bash", "-c", step["run"]], cwd=repo, env=env, check=True, capture_output=True, text=True
    )
    lines = output.read_text(encoding="utf-8").splitlines()
    outputs = dict(line.partition("=")[::2] for line in lines)
    assert len(outputs) == len(lines) == len(OUTPUTS), lines
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
    found = _run_filter(repo, tmp_path)
    assert {key: found[key] for key in ("release", "grammars")} == {
        "release": release,
        "grammars": grammars,
    }


@pytest.mark.parametrize(
    ("change", "corpus", "node", "facade"),
    [
        # A query engine alone: the Rust tests and golden compare hold it.
        ({"crates/opentide-kql/src/lib.rs": "changed\n"}, "false", "false", "false"),
        ({"src/opentide/cli.py": "changed\n"}, "false", "false", "false"),
        ({"docs/usage/index.md": "changed\n"}, "false", "false", "false"),
        # The corpora's comparisons, the crates they hold to the oracle, their data.
        ({"xtask/src/corpus/cli.rs": "changed\n"}, "true", "false", "false"),
        ({"crates/opentide-schema/src/lib.rs": "changed\n"}, "true", "false", "false"),
        ({"crates/opentide-workspace/src/lib.rs": "changed\n"}, "true", "false", "false"),
        ({"crates/opentide-lsp/src/main.rs": "changed\n"}, "true", "false", "false"),
        ({"tests/corpora/faults.toml": "changed\n"}, "true", "false", "false"),
        ({"tests/golden/cases.toml": "changed\n"}, "true", "false", "false"),
        # The Node package and the facade it binds.
        ({"bindings/node/src/lib.rs": "changed\n"}, "false", "true", "false"),
        ({"crates/opentide/src/lib.rs": "changed\n"}, "false", "true", "true"),
        # The lockfile and ci.yml run all three.
        ({"Cargo.lock": "version = 4\n"}, "true", "true", "true"),
        ({".github/workflows/ci.yml": "name: CI\n"}, "true", "true", "true"),
        # Near misses.
        ({"crates/opentide-cli/src/lib.rs": "changed\n"}, "false", "false", "false"),
        ({"bindings/python/src/lib.rs": "changed\n"}, "false", "false", "false"),
    ],
)
def test_the_filter_scopes_the_corpora_node_and_facade(
    tmp_path: Path, change: dict[str, str | None], corpus: str, node: str, facade: str
) -> None:
    golden = _golden()
    repo = _pull_request(golden, tmp_path, {"Cargo.lock": "version = 3\n"}, change)
    found = _run_filter(repo, tmp_path)
    assert {key: found[key] for key in ("corpus", "node", "facade")} == {
        "corpus": corpus,
        "node": node,
        "facade": facade,
    }


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
    quiet = QUIET
    everything = EVERYTHING
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
        # The unit matrix leaves out both: a full_set test never runs there.
        text = path.read_text(encoding="utf-8")
        assert "mark.cli_e2e" in text or "mark.cli_smoke" in text, path


# A pull request restores only its base branch's caches and the default
# branch's (development, which has no Rust jobs to save any). A pull request
# into a release train (train/catchup-0.28) found none, since nothing pushed
# to the train saved them. Every workflow whose push run saves a Rust cache
# runs on a push to a catch-up train too. Only the catch-up trains: the other
# train/ branches are pull requests' heads, whose pushes run as pull requests.
TRAINS = "train/catchup-*"
SAVES_ON_PUSH = ["ci.yml", "golden.yml", "schema.yml", "oracle.yml", "coverage.yml"]


@pytest.mark.parametrize("name", SAVES_ON_PUSH)
def test_a_push_to_a_release_train_saves_the_caches_its_pull_requests_read(name: str) -> None:
    branches = _triggers(_load(WORKFLOWS / name))["push"]["branches"]
    assert TRAINS in branches, name
    assert {"development", INTEGRATION} <= set(branches), name
    assert not [b for b in branches if b.startswith("train/") and b != TRAINS], branches


# ---- The lean pull request set ----------------------------------------------


def test_the_oldest_python_cell_skips_every_step_on_a_pull_request() -> None:
    """Test (3.10) is a required check: its cell starts on every pull request
    and runs only in the full set. Every step but the notice runs only when
    RUNS holds, or is the newest Python's alone (whose cell always runs)."""
    job = _ci_jobs()["test"]
    assert job["strategy"]["matrix"]["python-version"] == ["3.10", "3.14"]
    runs = str(job["env"]["RUNS"])
    assert runs == (
        "${{ matrix.python-version == '3.14' || github.event_name != 'pull_request' || "
        "contains(github.event.pull_request.labels.*.name, 'full-ci') }}"
    )
    notice, *steps = job["steps"]
    assert notice["if"] == "env.RUNS != 'true'"
    for step in steps:
        condition = str(step.get("if", ""))
        newest_only = (
            "matrix.python-version == env.COVERAGE_PYTHON" in condition
            and "!=" not in condition.split("COVERAGE_PYTHON")[0][-8:]
        )
        assert condition.startswith("env.RUNS == 'true'") or newest_only, step.get("name")


@pytest.mark.parametrize(
    ("os_name", "full", "result", "passes"),
    [
        ("ubuntu-latest", "false", "success", True),
        ("ubuntu-latest", "false", "failure", False),
        # macOS and Windows on a pull request: the Linux shards' result.
        ("macos-latest", "false", "success", True),
        ("windows-latest", "false", "failure", False),
        ("macos-latest", "true", "success", True),
        ("windows-latest", "true", "cancelled", False),
    ],
)
def test_the_engine_tests_check_of_each_os(
    os_name: str, full: str, result: str, passes: bool
) -> None:
    (step,) = _ci_jobs()["engine-test"]["steps"]
    done = subprocess.run(
        ["bash", "-ec", step["run"]],
        env={**os.environ, "RESULT": result, "OS": os_name, "FULL_SET": full},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (done.returncode == 0) is passes
    said = "runs in the full set" in done.stdout
    assert said is (os_name != "ubuntu-latest" and full != "true")


def _codeql_scope(repo: Path, tmp_path: Path, language: str, event: str, labels: str) -> str:
    workflow = _load(WORKFLOWS / "codeql.yml")
    step = next(s for s in workflow["jobs"]["analyze"]["steps"] if s.get("id") == "scope")
    output = tmp_path / "codeql_output"
    output.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "EVENT_NAME": event,
        "FULL_CI": "true" if "full-ci" in labels.split(",") else "false",
        "LANGUAGE": language,
        "PYTHON_PATHS": step["env"]["PYTHON_PATHS"],
        "ACTIONS_PATHS": step["env"]["ACTIONS_PATHS"],
        "GITHUB_OUTPUT": str(output),
    }
    subprocess.run(["bash", "-c", step["run"]], cwd=repo, env=env, check=True, capture_output=True)
    return output.read_text(encoding="utf-8").strip()


@pytest.mark.parametrize(
    ("change", "python", "actions"),
    [
        ({"crates/opentide-kql/src/lib.rs": "changed\n"}, "false", "false"),
        ({"docs/index.md": "changed\n"}, "false", "false"),
        ({"src/opentide/sdk.py": "changed\n"}, "true", "false"),
        ({"tests/test_ci/test_ci_scope.py": "changed\n"}, "true", "false"),
        ({"uv.lock": "changed\n"}, "true", "false"),
        ({".github/workflows/ci.yml": "name: CI\n"}, "false", "true"),
        ({".github/actions/x/action.yml": "name: X\n"}, "false", "true"),
    ],
)
def test_codeql_analyses_a_language_on_a_pull_request_that_changes_it(
    tmp_path: Path, change: dict[str, str | None], python: str, actions: str
) -> None:
    repo = _pull_request(_golden(), tmp_path, {}, change)
    assert _codeql_scope(repo, tmp_path, "python", "pull_request", "") == f"analyse={python}"
    assert _codeql_scope(repo, tmp_path, "actions", "pull_request", "") == f"analyse={actions}"
    # The label, a push, the weekly run: every language.
    for event, labels in (("pull_request", "full-ci"), ("push", ""), ("schedule", "")):
        assert _codeql_scope(repo, tmp_path, "python", event, labels) == "analyse=true"


def test_codeql_starts_every_language_and_gates_its_steps() -> None:
    """Its checks are required: the job starts on every pull request (no `if`,
    no path filter on the trigger) and its analysis steps read the scope."""
    workflow = _load(WORKFLOWS / "codeql.yml")
    assert _triggers(workflow)["pull_request"] is None
    job = workflow["jobs"]["analyze"]
    assert "if" not in job
    for step in job["steps"]:
        uses = str(step.get("uses", ""))
        if uses.startswith(("github/codeql-action/", "astral-sh/setup-uv")) or "uv sync" in str(
            step.get("run", "")
        ):
            assert "steps.scope.outputs.analyse == 'true'" in str(step.get("if")), uses


def test_lint_runs_actionlint_over_the_workflows() -> None:
    steps = _ci_jobs()["lint"]["steps"]
    (step,) = [s for s in steps if s.get("name") == "actionlint"]
    run = str(step["run"])
    # A pinned module version, verified by Go's checksum database.
    module = r"github\.com/rhysd/actionlint/cmd/actionlint@v\d+\.\d+\.\d+\n"
    assert re.search(r"go install " + module, run)
    assert '"${RUNNER_TEMP}/bin/actionlint"' in run
    assert (ROOT / ".github" / "actionlint.yaml").is_file()


def test_a_push_run_names_the_merged_pull_request() -> None:
    """A full-set failure on a base branch is visible as the merge it came from."""
    run_name = str(_load(CI)["run-name"])
    assert "github.event.head_commit.message" in run_name
    assert "github.event_name == 'push'" in run_name


# ---- The oracles: each reference on its own language's inputs -----------------

ORACLE_JOBS = {"kql": "kql", "spl": "spl", "falco": "falco", "elastic": "elastic"}
ORACLE_JOBS["elasticsearch"] = "elastic"


def _oracle_scope(repo: Path, tmp_path: Path, event: str = "pull_request") -> dict[str, str]:
    step = next(
        s
        for s in _load(WORKFLOWS / "oracle.yml")["jobs"]["changes"]["steps"]
        if s.get("id") == "paths"
    )
    output = tmp_path / "oracle_output"
    output.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "EVENT_NAME": event,
        "FULL_CI": "false",
        **{key: str(value) for key, value in step["env"].items() if key.endswith("_PATHS")},
        "GITHUB_OUTPUT": str(output),
    }
    subprocess.run(["bash", "-c", step["run"]], cwd=repo, env=env, check=True, capture_output=True)
    lines = output.read_text(encoding="utf-8").splitlines()
    return dict(line.partition("=")[::2] for line in lines)


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"crates/opentide-kql/src/lib.rs": "x\n"}, {"kql"}),
        ({"data/catalogs/spl/commands.toml": "x\n"}, {"spl"}),
        ({"scripts/engine/oracles/falco/run.py": "x\n"}, {"falco"}),
        ({"crates/opentide-lucene/src/lib.rs": "x\n"}, {"elastic"}),
        ({"grammars/tree-sitter-opentide-esql/grammar.js": "x\n"}, {"elastic"}),
        # What every language builds on: every reference.
        ({"crates/opentide-analysis/src/lib.rs": "x\n"}, {"kql", "spl", "falco", "elastic"}),
        ({"scripts/engine/oracles/oracle.py": "x\n"}, {"kql", "spl", "falco", "elastic"}),
        ({"Cargo.lock": "version = 4\n"}, {"kql", "spl", "falco", "elastic"}),
        # Near misses.
        ({"crates/opentide-cql/src/lib.rs": "x\n"}, set()),
        ({"docs/engine/kql.md": "x\n"}, set()),
    ],
)
def test_each_oracle_runs_on_its_languages_inputs(
    tmp_path: Path, change: dict[str, str | None], expected: set[str]
) -> None:
    repo = _pull_request(_golden(), tmp_path, {"Cargo.lock": "version = 3\n"}, change)
    found = _oracle_scope(repo, tmp_path)
    assert {key for key, value in found.items() if value == "true"} == expected
    assert set(found) == set(ORACLE_JOBS.values())
    # Not a pull request: every reference.
    assert set(_oracle_scope(repo, tmp_path, event="push").values()) == {"true"}


def test_each_oracle_job_reads_its_scope() -> None:
    jobs = _load(WORKFLOWS / "oracle.yml")["jobs"]
    for job_id, output in ORACLE_JOBS.items():
        assert _needs(jobs[job_id]) == ["changes"], job_id
        assert jobs[job_id]["if"] == _paths_condition(output), job_id


def test_the_pinned_elastic_references_are_cached_and_checked() -> None:
    """Lucene's jars and the Elastic grammars come from Maven Central and
    GitHub: cached under oracle.py's pins (Maven answered HTTP 429 on #1041),
    saved from pushes only, each file's SHA-256 checked by oracle.py."""
    steps = _load(WORKFLOWS / "oracle.yml")["jobs"]["elastic"]["steps"]
    restore = next(s for s in steps if str(s.get("uses", "")).startswith("actions/cache/restore@"))
    save = next(s for s in steps if str(s.get("uses", "")).startswith("actions/cache/save@"))
    key = "oracle-references-${{ hashFiles('scripts/engine/oracles/oracle.py') }}"
    assert restore["with"]["key"] == save["with"]["key"] == key
    assert restore["with"]["path"] == save["with"]["path"]
    assert "*.jar" in restore["with"]["path"]
    assert str(save["if"]).startswith("github.event_name == 'push'")
    names = [str(s.get("name", "")) for s in steps]
    assert names.index("Restore the pinned references") < names.index("Elastic oracles")
    oracle = (ROOT / "scripts" / "engine" / "oracles" / "oracle.py").read_text(encoding="utf-8")
    # The pins and the check the cache relies on.
    assert '"lucene-core.jar": (' in oracle and "sha256(path.read_bytes())" in oracle


def test_a_pull_request_builds_the_sdist_and_the_full_set_the_wheel_from_it() -> None:
    """The wheel from the sdist took 4 to 6 minutes of Lint in a temporary
    directory sccache cannot reuse; the full set still builds it (and
    `packages` every installable wheel). A pull request checks the sdist."""
    steps = {step.get("name"): step for step in _ci_jobs()["lint"]["steps"]}
    assert steps["Build the sdist"]["run"] == "uv build --sdist"
    assert steps["Twine check"]["run"] == "uvx twine check dist/*"
    for name in ("Build the sdist", "Twine check"):
        assert "if" not in steps[name], name
    assert steps["Build the wheel from the sdist"]["if"] == FULL_SET


def test_engine_lint_builds_xtask_once() -> None:
    """One cargo build of xtask and the language server, whose binaries the
    later steps run: no `cargo xtask` or `cargo run` builds them again."""
    steps = _ci_jobs()["engine"]["steps"]
    runs = [str(step.get("run", "")) for step in steps]
    build = "cargo build --locked --package xtask --package opentide-lsp"
    assert runs.count(build) == 1
    built = runs.index(build)
    for n, run in enumerate(runs):
        for line in run.splitlines():
            assert not re.search(r"\bcargo (xtask|run)\b", line), line
            if "target/debug/" in line:
                assert n > built, line
    used = "\n".join(runs)
    for command in ("check-layers", "cassettes check", "codegen --check"):
        assert f"target/debug/xtask {command}" in used, command
    assert "target/debug/opentide-lsp generate-highlights --check" in used


# The Linux engine-test shards (#841): by package, so that each shard builds
# only its packages' test binaries (sccache does not cache a test harness).
def _workspace_packages() -> dict[str, Path]:
    """Every member of the root Cargo.toml's workspace: its package name and
    directory."""
    import tomllib

    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    packages = {}
    for member in manifest["workspace"]["members"]:
        member_manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text("utf-8"))
        packages[member_manifest["package"]["name"]] = ROOT / member
    return packages


def _linux_shards() -> list[list[str]]:
    from tests.test_ci import ci_matrix

    cells = ci_matrix.cells(_ci_jobs()["engine-test-part"], "pull")
    assert {cell["os"] for cell in cells} == {"ubuntu-latest"}
    return [
        ci_matrix.selection(cell["packages"])[0]
        for cell in sorted(cells, key=lambda c: int(c["shard"]))
    ]


def test_the_engine_test_shards_cover_every_package_once() -> None:
    """A package in no shard would never be tested on a pull request; one in
    two would be built and tested twice."""
    shards = _linux_shards()
    named = [package for shard in shards for package in shard]
    assert len(named) == len(set(named)), "a package is in two shards"
    assert set(named) == set(_workspace_packages())


def _weight(directory: Path) -> float:
    """What a package costs a shard: its lines of Rust (the unit-test harness
    compiles them all again) and three thousand per test binary it links."""
    lines = sum(
        len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        for path in directory.rglob("*.rs")
        if "target" not in path.parts
    )
    tests = directory / "tests"
    binaries = [*tests.glob("*.rs"), *tests.glob("*/main.rs")] if tests.is_dir() else []
    return lines + 3000 * len(binaries)


def test_the_engine_test_shards_take_even_shares() -> None:
    """The slowest shard is the gate's time: none carries much more than its
    share, so a new heavy crate goes where it keeps them even."""
    packages = _workspace_packages()
    weights = [sum(_weight(packages[name]) for name in shard) for shard in _linux_shards()]
    mean = sum(weights) / len(weights)
    assert max(weights) <= 1.25 * mean, [round(w / mean, 2) for w in weights]


def _features(arguments: list[str]) -> dict[str, set[str]]:
    """The features cargo enables on each workspace member for a build of
    `arguments` (`--workspace`, or a shard's `-p` and `--features`)."""
    import shutil

    cargo = shutil.which("cargo")
    assert cargo, "cargo resolves the features"
    tree = subprocess.run(
        [
            cargo,
            "tree",
            "--locked",
            "-e",
            "features",
            "-f",
            "{p} [{f}]",
            "--prefix",
            "none",
            *arguments,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    members = set(_workspace_packages())
    found: dict[str, set[str]] = {}
    for line in tree.splitlines():
        match = re.match(r"(\S+) v\S+(?: \([^)]*\))? \[(.*)\]$", line)
        if match and match.group(1) in members:
            found.setdefault(match.group(1), set()).update(
                feature for feature in match.group(2).split(",") if feature
            )
    return found


def test_each_shard_builds_its_packages_with_the_workspaces_features() -> None:
    """`--workspace` unifies features: the bindings turn on the facade's
    `cli`, `python` and the rest, and opentide-schema's `python`, which gate
    tests (opentide-schema's trybuild cases are `cfg(feature = "python")`).
    A shard of `-p` alone would build those packages without them and skip
    their tests without a word, so each shard names them with `--features`."""
    from tests.test_ci import ci_matrix

    whole = _features(["--workspace"])
    cells = ci_matrix.cells(_ci_jobs()["engine-test-part"], "pull")
    for cell in cells:
        packages, _ = ci_matrix.selection(cell["packages"])
        shard = _features(cell["packages"].split())
        for package in packages:
            missing = whole.get(package, set()) - shard.get(package, set())
            assert not missing, f"shard {cell['shard']}: {package} without {sorted(missing)}"


# opentide-schema's compile-fail cases (`opentide-schema::ui`, trybuild): the
# full set, and a pull request that changes what they compile.
UI_INPUTS = [
    "crates/opentide-schema-derive/src/lib.rs",
    "crates/opentide-schema/src/model/rule.rs",
    "crates/opentide-schema/tests/ui.rs",
    "crates/opentide-schema/tests/ui/pyclass_generic.stderr",
    "crates/opentide-schema/Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
]
NOT_UI_INPUTS = ["crates/opentide-cli/src/main.rs", "docs/cli/validate.md", "src/opentide/sdk.py"]


def _ui_step() -> dict[str, Any]:
    (step,) = [s for s in _ci_jobs()["engine-test-part"]["steps"] if s.get("id") == "ui"]
    return step


def _ui_decision(tmp_path: Path, changed: list[str], full_set: str, merge: bool = True) -> str:
    """The step's own shell in a repository whose HEAD merges a change of
    `changed` into a base, as a pull request's checkout does."""

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )

    git("init", "-q", "-b", "base")
    (tmp_path / "README").write_text("base\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    git("switch", "-q", "-c", "change")
    for path in changed:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("changed\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-q", "-m", "change")
    if merge:
        git("switch", "-q", "base")
        (tmp_path / "BASE").write_text("moved on\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-q", "-m", "base moves")
        git("merge", "-q", "--no-ff", "-m", "merge", "change")
    step = _ui_step()
    output = tmp_path / "output"
    subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "FULL_SET": full_set,
            "UI_PATHS": step["env"]["UI_PATHS"],
            "GITHUB_OUTPUT": str(output),
        },
        check=True,
        capture_output=True,
    )
    return output.read_text(encoding="utf-8").strip()


@pytest.mark.parametrize("path", UI_INPUTS)
def test_the_compile_fail_cases_run_when_their_inputs_change(tmp_path: Path, path: str) -> None:
    assert _ui_decision(tmp_path, [path, "docs/cli/validate.md"], "false") == "run=true"


def test_the_compile_fail_cases_wait_for_the_full_set_otherwise(tmp_path: Path) -> None:
    assert _ui_decision(tmp_path, NOT_UI_INPUTS, "false") == "run=false"


def test_the_compile_fail_cases_run_in_the_full_set(tmp_path: Path) -> None:
    assert _ui_decision(tmp_path, NOT_UI_INPUTS, "true") == "run=true"


def test_the_compile_fail_cases_run_when_the_merge_cannot_be_read(tmp_path: Path) -> None:
    """No second parent (a push, or a checkout without the merge): fail open."""
    assert _ui_decision(tmp_path, NOT_UI_INPUTS, "false", merge=False) == "run=true"


def test_the_compile_fail_filter_names_the_trybuild_binary() -> None:
    """The filter excludes exactly the test binary of crates/opentide-schema/tests/ui.rs,
    in the shard that builds it, only when the step said not to run it; the
    checkout reads the merge's parent."""
    from tests.test_ci import ci_matrix

    job = _ci_jobs()["engine-test-part"]
    assert job["steps"][0]["with"]["fetch-depth"] == 2
    assert (ROOT / "crates" / "opentide-schema" / "tests" / "ui.rs").is_file()
    step = _ui_step()
    assert step["env"]["FULL_SET"] == "${{ " + FULL_SET + " }}"
    (nextest,) = [s for s in job["steps"] if "cargo nextest run" in str(s.get("run", ""))]
    assert nextest["env"]["UI"] == "${{ steps.ui.outputs.run }}"
    assert "filter=(-E 'not binary_id(opentide-schema::ui)')" in nextest["run"]
    condition = 'if [[ "${UI}" != true && " ${PACKAGES} " == *" -p opentide-schema "* ]]; then'
    assert condition in nextest["run"]
    owners = [
        cell
        for cell in ci_matrix.cells(job, "pull")
        if "opentide-schema" in ci_matrix.selection(cell["packages"])[0]
    ]
    assert len(owners) == 1 and f" {owners[0]['packages']} ".count(" -p opentide-schema ") == 1
