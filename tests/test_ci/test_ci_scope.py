"""What runs on a pull request, a push, a release pull request and nightly.

ci.yml's tiers (.github/AGENTS.md; scripts/ci/changes.py decides which):

- **`changes`** runs first, on every run: the mode (``pr``, ``full``,
  ``nightly``), whether it is a release, the affected crates and the areas.
- **The PR gate**, Linux only: each job needs `changes` and runs only when its
  area is marked (``needs.changes.outputs.<area> == 'true'``). ``build`` is the
  one job that compiles the workspace for it; the Rust tests, the Python suite
  and E2E run from what it built. A push and Run workflow (scope ``full``) mark
  every area.
- **The release tier**: on a release pull request and Run workflow with scope
  ``release`` (``release == 'true'``); the packages, the release dry run, the
  crates' package and the publish dry run also nightly. macOS and Windows run
  here and in the nightly only.
- **The nightly** (``mode == 'nightly'``): never on a pull request or a push,
  so it never gates; ``nightly-report`` files its failures in one issue.
- **One required check**, ``PR gate``: it needs every job but the nightly's,
  runs whatever they did (``always()``) and fails unless `changes` succeeded
  and every other job it needs succeeded or was skipped.

The Python oracle's comparisons left CI (test_golden_workflow.py).
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest
from tests.test_ci import ci_matrix
from tests.test_ci.ci_steps import (
    CI,
    INTEGRATION,
    NIGHTLY,
    NIGHTLY_JOBS,
    OWN,
    PR_GATE,
    PR_GATE_IF,
    RELEASE,
    RELEASE_TIER,
    ROOT,
    WORKFLOWS,
    changes,
    ci_jobs,
    load,
    merged_checkout,
    needs,
    run_step,
    step,
    triggers,
)

# The reusable workflows the nightly calls: no trigger of their own but Run workflow.
NIGHTLY_WORKFLOWS = {
    "coverage": "coverage.yml",
    "benchmarks": "bench.yml",
    "oracle": "oracle.yml",
    "schema": "schema.yml",
}
# What a pull request starts: ci.yml and CodeQL.
ON_PULL_REQUESTS = {"ci.yml", "codeql.yml"}


def test_every_ci_job_has_one_tier() -> None:
    tiers = [set(PR_GATE), set(RELEASE_TIER), NIGHTLY_JOBS, OWN]
    every = [job for tier in tiers for job in tier]
    assert len(every) == len(set(every)), "a job is in two tiers"
    assert set(ci_jobs()) == set(every)


def test_changes_runs_first_and_names_every_output_of_the_plan() -> None:
    """`changes` needs nothing and runs on every run; its outputs are exactly
    the keys scripts/ci/changes.py writes, each read from the step."""
    job = ci_jobs()["changes"]
    assert "needs" not in job and "if" not in job
    assert job["runs-on"] == "ubuntu-latest"
    keys = set(changes().Plan(mode="pr").outputs([]))
    assert set(job["outputs"]) == keys
    for key, value in job["outputs"].items():
        assert value == f"${{{{ steps.plan.outputs.{key} }}}}", key
    plan = step("changes", step_id="plan")
    assert plan["run"] == "python3 scripts/ci/changes.py"
    # A pull request's base...head needs the history.
    assert job["steps"][0]["with"]["fetch-depth"] == 0
    for name in ("EVENT", "SCOPE", "BASE_SHA", "HEAD_SHA", "BASE_REF", "HEAD_REF", "LABELS"):
        assert name in plan["env"], name


@pytest.mark.parametrize("job_id", sorted(PR_GATE))
def test_a_gate_job_runs_when_changes_marks_its_area(job_id: str) -> None:
    job = ci_jobs()[job_id]
    assert "changes" in needs(job), job_id
    assert job.get("if") == PR_GATE_IF[job_id], job_id
    assert "continue-on-error" not in job, job_id
    # Linux only: macOS and Windows are the release tier's and the nightly's.
    assert job.get("runs-on") == "ubuntu-latest", job_id
    assert set(needs(job)) <= {"changes", "build"}, (job_id, needs(job))


@pytest.mark.parametrize("job_id", sorted(PR_GATE))
def test_a_gate_job_reads_an_output_changes_writes(job_id: str) -> None:
    outputs = set(ci_jobs()["changes"]["outputs"])
    for area in re.findall(r"needs\.changes\.outputs\.([\w-]+)", PR_GATE_IF[job_id]):
        assert area in outputs, (job_id, area)


@pytest.mark.parametrize(
    "job_id",
    sorted(j for j, job in ci_jobs().items() if "build" in needs(job) and j not in OWN),
)
def test_a_job_that_needs_the_build_runs_only_when_the_build_does(job_id: str) -> None:
    """A job that needs `build` is skipped with it: whatever marks the job's
    area must mark `build` too (changes.py's outputs), or the job never runs."""
    module = changes()
    condition = str(ci_jobs()[job_id]["if"])
    if condition == NIGHTLY:
        plan = module.everything(module.Plan(mode="nightly"), ["a"], "nightly")
        assert plan.outputs(["a"])["build"] == "true"
        return
    match = re.fullmatch(r"needs\.changes\.outputs\.([\w-]+) == 'true'", condition)
    assert match, (job_id, condition)
    area = match.group(1)
    crates = {"a"} if area == "rust" else set()
    plan = module.Plan(mode="pr", areas={area} - {"rust"}, crates=crates)
    assert plan.outputs(["a", "b"])[area] == "true", job_id
    assert plan.outputs(["a", "b"])["build"] == "true", job_id


@pytest.mark.parametrize(("job_id", "condition"), sorted(RELEASE_TIER.items()))
def test_the_release_tier_runs_on_a_release(job_id: str, condition: str | None) -> None:
    job = ci_jobs()[job_id]
    assert "changes" in needs(job), job_id
    assert job.get("if") == condition, job_id
    if condition is None:
        # The implicit success(): skipped whenever a job it needs is.
        gated = [n for n in needs(job) if n != "changes"]
        assert gated and all(RELEASE_TIER.get(n) == RELEASE for n in gated), job_id


@pytest.mark.parametrize("job_id", sorted(NIGHTLY_JOBS))
def test_the_nightly_runs_nightly_only(job_id: str) -> None:
    job = ci_jobs()[job_id]
    assert job.get("if") == NIGHTLY, job_id
    assert "changes" in needs(job), job_id


def test_the_gate_needs_every_job_but_the_nightlys() -> None:
    """A job the gate does not need could fail without failing the required
    check; a nightly job it needed would hold every pull request's check on a
    job that never runs there (skipped, so harmless, but a nightly failure
    would turn the nightly's gate red for a reason no pull request has)."""
    jobs = ci_jobs()
    gate = jobs["gate"]
    expected = {j for j in jobs if j not in NIGHTLY_JOBS and j not in {"gate", "nightly-report"}}
    assert set(needs(gate)) == expected
    assert len(needs(gate)) == len(set(needs(gate)))
    assert gate["name"] == "PR gate"
    # A failed job must not skip the gate: a skipped required check passes.
    assert gate["if"] == "always()"
    assert gate["runs-on"] == "ubuntu-latest"
    assert gate["permissions"] == {}
    assert "continue-on-error" not in gate


def _gate(results: dict[str, str]) -> int:
    (spec,) = ci_jobs()["gate"]["steps"]
    assert spec["env"]["NEEDS"] == "${{ toJSON(needs) }}"
    payload = {job: {"result": result, "outputs": {}} for job, result in results.items()}
    done = subprocess.run(
        ["bash", "-e", "-c", spec["run"]],
        env={**os.environ, "NEEDS": json.dumps(payload)},
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode


@pytest.mark.parametrize(
    ("results", "passes"),
    [
        ({"changes": "success", "lint": "success", "build": "success"}, True),
        ({"changes": "success", "lint": "skipped", "build": "skipped"}, True),
        ({"changes": "success", "lint": "success", "build": "failure"}, False),
        ({"changes": "success", "lint": "cancelled", "build": "success"}, False),
        # `changes` decides what runs: skipped or failed, nothing was checked.
        ({"changes": "skipped", "lint": "skipped", "build": "skipped"}, False),
        ({"changes": "failure", "lint": "skipped", "build": "skipped"}, False),
        ({"changes": "cancelled", "lint": "skipped", "build": "skipped"}, False),
    ],
)
def test_the_gate_fails_unless_every_needed_job_passed(
    results: dict[str, str], passes: bool
) -> None:
    assert (_gate(results) == 0) is passes, results


def test_the_nightly_report_files_every_nightly_failure() -> None:
    jobs = ci_jobs()
    report = jobs["nightly-report"]
    assert set(needs(report)) == NIGHTLY_JOBS | {"changes", "gate"}
    assert report["if"] == f"always() && {NIGHTLY}"
    # The one ci.yml job that writes issues, and it runs no repository code.
    assert report["permissions"] == {"actions": "read", "issues": "write"}
    for spec in report["steps"]:
        assert "uses" not in spec, spec.get("name")
        assert not re.search(r"\b(cargo|uv|npm|python3?|bash scripts)\b", str(spec.get("run", "")))
    assert "nightly-failure" in json.dumps(report["steps"])
    writes = {
        job_id: {
            scope for scope, level in (job.get("permissions") or {}).items() if level == "write"
        }
        for job_id, job in jobs.items()
    }
    # The Python job reports its tests and coverage.
    assert {job_id: scopes for job_id, scopes in writes.items() if scopes} == {
        "nightly-report": {"issues"},
        "python": {"checks", "code-quality"},
    }


def _oses(job: dict[str, Any]) -> set[str]:
    return {
        re.sub(r"\$\{\{\s*matrix\.os\s*\}\}", cell.get("os", ""), str(job.get("runs-on")))
        for cell in ci_matrix.cells(job)
    }


def test_macos_and_windows_run_in_the_release_tier_and_the_nightly_only() -> None:
    jobs = ci_jobs()
    elsewhere = set()
    for job_id, job in jobs.items():
        if "uses" in job:
            continue
        oses = _oses(job)
        if job_id in RELEASE_TIER or job_id in NIGHTLY_JOBS:
            elsewhere |= oses
        else:
            assert oses == {"ubuntu-latest"}, (job_id, oses)
    assert {"macos-latest", "windows-latest"} <= elsewhere
    assert _oses(jobs["engine-test-os"]) == {"macos-latest", "windows-latest"}


def test_ci_runs_on_pull_requests_pushes_nightly_and_on_demand() -> None:
    workflow = load(CI)
    on = triggers(workflow)
    assert set(on) == {"push", "pull_request", "workflow_dispatch", "schedule"}
    assert {"development", INTEGRATION, "train/*"} <= set(on["push"]["branches"])
    pull = on["pull_request"]
    # Every base: the base branches and the branch below a stacked pull request.
    assert "branches" not in pull
    # `labeled`: the `release` label runs the release tier; no path filter.
    assert set(pull["types"]) == {"opened", "synchronize", "reopened", "labeled"}
    assert "paths" not in pull and "paths-ignore" not in pull
    scope = on["workflow_dispatch"]["inputs"]["scope"]
    assert scope["type"] == "choice"
    assert scope["options"] == ["full", "release", "nightly"]
    assert scope["default"] == "full"
    assert len(on["schedule"]) == 1
    # The nightly run and a push to development must not cancel each other.
    assert "github.event_name" in workflow["concurrency"]["group"]
    assert "full-ci" not in CI.read_text(encoding="utf-8")


@pytest.mark.parametrize(("job_id", "name"), sorted(NIGHTLY_WORKFLOWS.items()))
def test_the_nightlys_workflows_are_called_by_it_only(job_id: str, name: str) -> None:
    workflow = load(WORKFLOWS / name)
    assert set(triggers(workflow)) == {"workflow_call", "workflow_dispatch"}, name
    job = ci_jobs()[job_id]
    assert job["uses"] == f"./.github/workflows/{name}"
    assert job["if"] == NIGHTLY
    for other_id, other in workflow["jobs"].items():
        assert "needs.changes" not in str(other.get("if", "")), (name, other_id)


def test_every_called_workflow_is_called_by_ci_only() -> None:
    """build-packages.yml, engine-release-build.yml and publish-dry-run.yml are
    called (publish.yml calls the first two too); none runs by itself on a
    pull request, a push or a schedule."""
    called = {
        job["uses"].removeprefix("./.github/workflows/")
        for job in ci_jobs().values()
        if "uses" in job
    }
    assert called == {
        *NIGHTLY_WORKFLOWS.values(),
        "build-packages.yml",
        "engine-release-build.yml",
        "publish-dry-run.yml",
    }
    for name in called:
        on = set(triggers(load(WORKFLOWS / name)))
        assert "workflow_call" in on, name
        assert not on & {"push", "pull_request", "pull_request_target", "schedule"}, (name, on)


def test_only_ci_and_codeql_run_on_a_pull_request() -> None:
    on_pull_requests = {
        path.name
        for path in sorted(WORKFLOWS.glob("*.yml"))
        if {"pull_request", "pull_request_target"} & set(triggers(load(path)))
    }
    assert on_pull_requests == ON_PULL_REQUESTS
    for path in sorted(WORKFLOWS.glob("*.yml")):
        assert "full-ci" not in "\n".join(
            str(job.get("if", "")) for job in (load(path).get("jobs") or {}).values()
        ), path.name


def test_the_retired_workflows_are_gone() -> None:
    """docs.yml is ci.yml's docs job; the stack comment, the golden workflows
    and the gathering jobs left with the old gate."""
    for name in ("docs.yml", "stack-comment.yml", "golden.yml", "golden-preview.yml"):
        assert not (WORKFLOWS / name).exists(), name
    assert not (ROOT / "scripts" / "github_stack_comment.py").exists()
    jobs = ci_jobs()
    for job_id in ("engine", "engine-test", "engine-test-part", "test", "cli-e2e"):
        assert job_id not in jobs, job_id
    assert "HEAVY_GOLDENS" not in CI.read_text(encoding="utf-8")


def _pytest_markers(job_id: str) -> list[str]:
    """The ``-m`` expression of each pytest step of ci.yml's *job_id*."""
    markers = []
    for spec in ci_jobs()[job_id]["steps"]:
        run = str(spec.get("run", ""))
        if "pytest" in run:
            words = shlex.split(run.replace("\\\n", " "))
            markers.append(words[words.index("-m") + 1])
    return markers


def test_python_runs_the_newest_on_a_pull_request_and_every_version_nightly() -> None:
    jobs = ci_jobs()
    assert str(load(CI)["env"]["COVERAGE_PYTHON"]) == "3.14"
    setup = next(
        s
        for s in jobs["python"]["steps"]
        if str(s.get("uses", "")).startswith("actions/setup-python@")
    )
    assert setup["with"]["python-version"] == "${{ env.COVERAGE_PYTHON }}"
    nightly = jobs["test-full"]["strategy"]["matrix"]["python-version"]
    assert nightly == ["3.10", "3.11", "3.12", "3.13"]
    # The same tests in every version.
    unit = "not cli_e2e and not cli_smoke and not gitlab_ci_lint"
    assert _pytest_markers("python") == [unit]
    assert _pytest_markers("test-full") == [unit]


def test_the_full_set_e2e_tests_run_nightly_only() -> None:
    """A test marked ``full_set`` (a wheel built per test, UC-4.5c, #835)
    runs in ``e2e-full``, nightly, never on a pull request: ``e2e`` leaves it
    out, and the unit jobs leave out ``cli_e2e``, which it carries."""
    assert _pytest_markers("e2e") == ["(cli_e2e or cli_smoke) and not full_set"]
    assert _pytest_markers("e2e-full") == ["full_set"]
    for job_id in ("python", "test-full"):
        markers = _pytest_markers(job_id)
        assert markers, job_id
        assert all("not cli_e2e" in marker for marker in markers), (job_id, markers)
    here = Path(__file__).resolve()
    marked = [
        path
        for path in sorted((ROOT / "tests").rglob("*.py"))
        if path.resolve() != here and "mark.full_set" in path.read_text(encoding="utf-8")
    ]
    assert marked, "no test is marked full_set: drop the marker and e2e-full"
    for path in marked:
        text = path.read_text(encoding="utf-8")
        assert "mark.cli_e2e" in text or "mark.cli_smoke" in text, path


# ---- The one build ------------------------------------------------------------

# What compiles the workspace (or a package of it) when a step runs it.
COMPILES = re.compile(
    r"\bcargo (?:\+\S+ )?(?:build|test|install|package|run|xtask|bench|rustc)\b"
    r"|\bcargo nextest (?:run|archive)\b"
    r"|\buv build(?! --sdist)\b"
    r"|\bmaturin\b"
)
# Gate jobs allowed to compile what the build does not: the facade with every
# feature (the archive holds the workspace's), its docs and semver checks.
COMPILES_ITS_OWN = {"facade"}
PREBUILT = "${{ github.workspace }}/.native/_native.abi3.so"


def _env(workflow: dict[str, Any], job: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    return {**(workflow.get("env") or {}), **(job.get("env") or {}), **(spec.get("env") or {})}


@pytest.mark.parametrize("job_id", sorted(set(PR_GATE) - {"build"}))
def test_only_the_build_compiles_the_gates_rust(job_id: str) -> None:
    """The gate builds the workspace once, in `build`: every other gate job
    runs the archive, installs the prebuilt extension, or compiles nothing.
    `uv sync` would compile the binding again unless it skips the project or
    hatch_build.py is handed the build's (OPENTIDE_ENGINE_PREBUILT)."""
    workflow = load(CI)
    job = workflow["jobs"][job_id]
    for spec in job.get("steps") or []:
        run = str(spec.get("run", "")).replace("\\\n", " ")
        env = _env(workflow, job, spec)
        for line in run.splitlines():
            found = COMPILES.search(line)
            if found and job_id not in COMPILES_ITS_OWN:
                # The archive's tests run without compiling.
                assert "nextest run" in found.group(0) and "--archive-file" in run, (
                    job_id,
                    line,
                )
            if re.search(r"\buv sync\b", line) and "--no-install-project" not in line:
                assert env.get("OPENTIDE_ENGINE_PREBUILT") == PREBUILT, (job_id, line)
            if re.search(r"\buv run\b", line) and "--no-sync" not in line:
                assert env.get("OPENTIDE_ENGINE_PREBUILT") == PREBUILT, (job_id, line)


def test_lint_compiles_nothing() -> None:
    """ruff and ty read the sources (ty the checked-in stubs of `_native`)."""
    job = ci_jobs()["lint"]
    runs = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "rustup" not in runs and not re.search(r"\bcargo\b", runs)
    assert "uv sync --group dev --no-install-project" in runs
    assert list((ROOT / "src" / "opentide" / "_native").glob("*.pyi")), "ty reads the stubs"


def test_the_build_compiles_once_and_checks_with_its_binaries() -> None:
    """The archive's build leaves xtask and the language server in
    target/debug, with the tests' features; the checks run those binaries.
    Nothing builds them again (a build without the tests' features
    recompiled for minutes), and no `cargo xtask` or `cargo run` either; the
    generated artifacts are checked without the oracle."""
    steps = ci_jobs()["build"]["steps"]
    runs = [str(s.get("run", "")) for s in steps]
    for run in runs:
        for line in run.splitlines():
            assert not re.search(r"\bcargo (xtask|run|build --locked -p xtask)\b", line), line
    archive = runs.index(next(r for r in runs if "cargo nextest archive" in r))
    bins = step("build", step_id="bins")
    found = next(n for n, s in enumerate(steps) if s.get("id") == "bins")
    assert archive < found
    assert bins["if"] == "env.RUST == 'true'"
    # An affected binary that is missing fails the build instead of skipping its checks.
    assert 'if [[ "${found}" == false && " ${CRATES} " == *" ${bin} "* ]]; then' in bins["run"]
    assert bins["env"]["CRATES"] == "${{ needs.changes.outputs.crates }}"
    used = "\n".join(runs)
    for command in ("check-layers", "cassettes check", "codegen --check"):
        assert f"target/debug/xtask {command}" in used, command
    assert "--oracle" not in used
    assert "target/debug/opentide-lsp generate-highlights --check" in used
    for name in ("Crate layers", "Deploy cassettes", "Generated artifacts"):
        assert step("build", name=name)["if"] == "steps.bins.outputs.xtask == 'true'", name
    assert (
        step("build", name="Generated highlights")["if"]
        == "steps.bins.outputs.opentide-lsp == 'true'"
    )
    # The doctests run the affected crates'.
    assert step("build", name="Doctests")["if"] == "env.RUST == 'true'"
    doctests = step("build", name="Doctests")["run"]
    assert re.search(r'cargo test --locked --doc "\$\{(\w+)\[@\]\}" "\$\{(\w+)\[@\]\}"', doctests)
    assert 'read -ra pkg_args <<< "${PACKAGES}"' in doctests


def test_the_build_archives_the_affected_crates_with_their_features() -> None:
    job = ci_jobs()["build"]
    assert job["env"]["PACKAGES"] == "${{ needs.changes.outputs.packages }}"
    assert job["env"]["FEATURES"] == "${{ needs.changes.outputs.features }}"
    assert job["env"]["RUSTFLAGS"].split()[0] == "-Dwarnings"
    archive = step("build", name="Build the Rust tests (nextest archive)")
    assert archive["if"] == "env.RUST == 'true'"
    assert (
        'cargo nextest archive --locked "${pkg_args[@]}" "${feature_args[@]}"'
        ' --archive-file "${RUNNER_TEMP}/tests.tar.zst"'
    ) in archive["run"]
    assert 'read -ra pkg_args <<< "${PACKAGES}"' in archive["run"]
    assert 'read -ra feature_args <<< "${FEATURES}"' in archive["run"]
    upload = step("build", name="Upload the test archive")
    assert upload["with"]["name"] == "nextest-archive"
    assert upload["with"]["path"] == "${{ runner.temp }}/tests.tar.zst"
    assert "continue-on-error" not in upload
    # Uploaded before the checks that need the target directory: the tests start early.
    names = [s.get("name") for s in job["steps"]]
    assert names.index("Upload the test archive") < names.index("Which checks the build can run")


def test_the_build_hands_its_extension_to_every_python_job() -> None:
    """hatch_build.py installs OPENTIDE_ENGINE_PREBUILT as is: the build's
    `_native` library, uploaded under the name the stubs' module takes."""
    jobs = ci_jobs()
    native = step("build", name="Build the _native extension")
    cargo = (ROOT / "bindings" / "python" / "Cargo.toml").read_text(encoding="utf-8")
    assert re.search(r'^\[lib\]\nname = "_native"', cargo, re.MULTILINE)
    assert "cargo build --locked -p opentide-native --lib" in native["run"]
    assert 'cp target/debug/lib_native.so "${RUNNER_TEMP}/native/_native.abi3.so"' in native["run"]
    upload = step("build", name="Upload the _native extension")
    assert upload["with"] == {
        "name": "native",
        "path": "${{ runner.temp }}/native/_native.abi3.so",
        "retention-days": 3,
    }
    assert native["if"] == upload["if"] == "env.PYTHON == 'true'"
    python = str(jobs["build"]["env"]["PYTHON"])
    downloaders = []
    for job_id, job in jobs.items():
        for spec in job.get("steps") or []:
            if not str(spec.get("uses", "")).startswith("actions/download-artifact@"):
                continue
            if (spec.get("with") or {}).get("name") != "native":
                continue
            downloaders.append(job_id)
            assert spec["with"]["path"] == ".native", job_id
            assert "build" in needs(job), job_id
            prebuilt = [
                _env({}, job, s).get("OPENTIDE_ENGINE_PREBUILT")
                for s in job["steps"]
                if "uv sync" in str(s.get("run", ""))
            ]
            assert prebuilt and set(prebuilt) == {PREBUILT}, job_id
            # The build makes the extension whenever this job runs.
            condition = str(job["if"])
            assert condition in python or condition == NIGHTLY, (job_id, condition)
            assert NIGHTLY in python
    assert {"python", "e2e", "gitlab-ci-lint", "node", "test-full", "e2e-full"} == set(downloaders)


def test_the_rust_tests_run_the_archive_in_partitions() -> None:
    job = ci_jobs()["rust-tests"]
    assert job["needs"] == ["changes", "build"]
    assert job["strategy"]["matrix"]["partition"] == (
        "${{ fromJSON(needs.changes.outputs.partitions) }}"
    )
    assert job["strategy"]["fail-fast"] is False
    assert "${{ matrix.partition }}/${{ strategy.job-total }}" in job["name"]
    runs = "\n".join(str(s.get("run", "")) for s in job["steps"])
    assert "rustup toolchain install" in runs  # xtask's tests run cargo
    nextest = step("rust-tests", name="cargo nextest (profile ci)")
    command = " ".join(nextest["run"].split())
    assert command.startswith("cargo nextest run --profile ci")
    assert '--archive-file "${RUNNER_TEMP}/tests.tar.zst"' in command
    assert '--workspace-remap "${GITHUB_WORKSPACE}"' in command
    assert '--partition "count:${PARTITION}/${TOTAL}"' in command
    assert nextest["env"] == {
        "PARTITION": "${{ matrix.partition }}",
        "TOTAL": "${{ strategy.job-total }}",
    }
    # The compile-fail cases compile at test time: `build` runs them.
    assert "-E 'not binary_id(/^opentide-schema::ui$/)'" in command
    download = next(
        s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/download-artifact@")
    )
    assert download["with"] == {"name": "nextest-archive", "path": "${{ runner.temp }}"}


# ---- opentide-schema's compile-fail cases, in `build` ------------------------

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


def _ui_decision(tmp_path: Path, changed: list[str], mode: str, merge: bool = True) -> str:
    repo = merged_checkout(tmp_path / "repo", changed, merge=merge)
    return run_step(step("build", step_id="ui"), repo, {"MODE": mode})["run"]


@pytest.mark.parametrize("path", UI_INPUTS)
def test_the_compile_fail_cases_run_when_their_inputs_change(tmp_path: Path, path: str) -> None:
    assert _ui_decision(tmp_path, [path, "docs/cli/validate.md"], "pr") == "true"


def test_the_compile_fail_cases_wait_for_a_push_otherwise(tmp_path: Path) -> None:
    assert _ui_decision(tmp_path, NOT_UI_INPUTS, "pr") == "false"


@pytest.mark.parametrize("mode", ["full", "nightly"])
def test_the_compile_fail_cases_run_on_every_push_and_nightly(tmp_path: Path, mode: str) -> None:
    assert _ui_decision(tmp_path, NOT_UI_INPUTS, mode) == "true"


def test_the_compile_fail_cases_run_when_the_merge_cannot_be_read(tmp_path: Path) -> None:
    """No second parent (a checkout without the merge): fail open."""
    assert _ui_decision(tmp_path, NOT_UI_INPUTS, "pr", merge=False) == "true"


def test_the_compile_fail_step_names_the_trybuild_binary() -> None:
    job = ci_jobs()["build"]
    assert job["steps"][0]["with"]["fetch-depth"] == 2
    assert (ROOT / "crates" / "opentide-schema" / "tests" / "ui.rs").is_file()
    decision = step("build", step_id="ui")
    assert decision["env"]["MODE"] == "${{ needs.changes.outputs.mode }}"
    cases = step("build", name="opentide-schema's compile-fail cases")
    assert cases["if"] == "steps.ui.outputs.run == 'true'"
    assert cases["run"] == (
        "cargo nextest run --locked --profile ci -p opentide-schema"
        " --features opentide-schema/python -E 'binary_id(opentide-schema::ui)'"
    )


# ---- CodeQL, actionlint and run names ----------------------------------------


def _codeql_scope(repo: Path, tmp_path: Path, language: str, event: str) -> str:
    workflow = load(WORKFLOWS / "codeql.yml")
    spec = next(s for s in workflow["jobs"]["analyze"]["steps"] if s.get("id") == "scope")
    output = tmp_path / "codeql_output"
    output.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "EVENT_NAME": event,
        "LANGUAGE": language,
        "PYTHON_PATHS": spec["env"]["PYTHON_PATHS"],
        "ACTIONS_PATHS": spec["env"]["ACTIONS_PATHS"],
        "GITHUB_OUTPUT": str(output),
    }
    subprocess.run(["bash", "-c", spec["run"]], cwd=repo, env=env, check=True, capture_output=True)
    return output.read_text(encoding="utf-8").strip()


@pytest.mark.parametrize(
    ("change", "python", "actions"),
    [
        ("crates/opentide-kql/src/lib.rs", "false", "false"),
        ("docs/index.md", "false", "false"),
        ("src/opentide/sdk.py", "true", "false"),
        ("tests/test_ci/test_ci_scope.py", "true", "false"),
        ("uv.lock", "true", "false"),
        (".github/workflows/ci.yml", "false", "true"),
        (".github/actions/x/action.yml", "false", "true"),
    ],
)
def test_codeql_analyses_a_language_on_a_pull_request_that_changes_it(
    tmp_path: Path, change: str, python: str, actions: str
) -> None:
    repo = merged_checkout(tmp_path / "repo", [change])
    assert _codeql_scope(repo, tmp_path, "python", "pull_request") == f"analyse={python}"
    assert _codeql_scope(repo, tmp_path, "actions", "pull_request") == f"analyse={actions}"
    # A push and the weekly run: every language.
    for event in ("push", "schedule"):
        assert _codeql_scope(repo, tmp_path, "python", event) == "analyse=true"


def test_codeql_starts_on_a_pull_request_that_changes_what_it_reads() -> None:
    """Not a required check (.github/AGENTS.md): a pull request starts it only
    when it changes Python or a workflow; each analysis step still reads the
    scope, so a language the change does not touch is not analysed."""
    workflow = load(WORKFLOWS / "codeql.yml")
    pull = triggers(workflow)["pull_request"]
    assert "branches" not in pull
    assert set(pull["paths"]) == {
        "**/*.py",
        "pyproject.toml",
        "uv.lock",
        ".github/workflows/**",
        ".github/actions/**",
    }
    job = workflow["jobs"]["analyze"]
    assert "if" not in job
    for spec in job["steps"]:
        uses = str(spec.get("uses", ""))
        if uses.startswith(("github/codeql-action/", "astral-sh/setup-uv")) or "uv sync" in str(
            spec.get("run", "")
        ):
            assert "steps.scope.outputs.analyse == 'true'" in str(spec.get("if")), uses


def test_codeql_starts_on_every_file_its_scope_analyses() -> None:
    workflow = load(WORKFLOWS / "codeql.yml")
    paths = triggers(workflow)["pull_request"]["paths"]
    scope = next(s for s in workflow["jobs"]["analyze"]["steps"] if s.get("id") == "scope")
    for variable in ("PYTHON_PATHS", "ACTIONS_PATHS"):
        for pattern in scope["env"][variable].split():
            example = pattern.replace("*", "x")
            assert any(fnmatch.fnmatch(example, p.replace("**/", "")) for p in paths), example


def test_lint_runs_actionlint_over_the_workflows() -> None:
    spec = step("lint", name="actionlint")
    run = str(spec["run"])
    # A pinned module version, verified by Go's checksum database.
    module = r"github\.com/rhysd/actionlint/cmd/actionlint@v\d+\.\d+\.\d+\n"
    assert re.search(r"go install " + module, run)
    assert '"${RUNNER_TEMP}/bin/actionlint"' in run
    assert (ROOT / ".github" / "actionlint.yaml").is_file()


def test_lint_builds_the_sdist_and_the_release_tier_installs_it() -> None:
    """Lint checks the sdist with twine; a release builds from it (smoke-sdist)."""
    assert step("lint", name="Build the sdist")["run"] == "uv build --sdist"
    assert step("lint", name="Twine check")["run"] == "uvx twine check dist/*"
    runs = [str(s.get("run", "")) for s in ci_jobs()["lint"]["steps"]]
    sdist = runs.index("uv build --sdist")
    # ty resolves opentide._version, which building the sdist writes.
    assert sdist < next(n for n, run in enumerate(runs) if "ty check" in run)
    assert "uv build --sdist" in json.dumps(ci_jobs()["sdist"]["steps"])
    assert ci_jobs()["smoke-sdist"]["needs"] == ["changes", "sdist"]
    assert "--no-binary opentide" in json.dumps(ci_jobs()["smoke-sdist"]["steps"])


def test_a_push_run_names_the_merged_pull_request() -> None:
    """A failure on a base branch is visible as the merge it came from."""
    run_name = str(load(CI)["run-name"])
    assert "github.event.head_commit.message" in run_name
    assert "github.event_name == 'push'" in run_name


def test_the_pinned_elastic_references_are_cached_and_checked() -> None:
    """Lucene's jars and the Elastic grammars come from Maven Central and
    GitHub: cached under oracle.py's pins (Maven answered HTTP 429 on #1041),
    saved by the scheduled run only, each file's SHA-256 checked by oracle.py."""
    steps = load(WORKFLOWS / "oracle.yml")["jobs"]["elastic"]["steps"]
    restore = next(s for s in steps if str(s.get("uses", "")).startswith("actions/cache/restore@"))
    save = next(s for s in steps if str(s.get("uses", "")).startswith("actions/cache/save@"))
    key = "oracle-references-${{ hashFiles('scripts/engine/oracles/oracle.py') }}"
    assert restore["with"]["key"] == save["with"]["key"] == key
    assert restore["with"]["path"] == save["with"]["path"]
    assert "*.jar" in restore["with"]["path"]
    assert str(save["if"]).startswith("github.event_name == 'schedule'")
    names = [str(s.get("name", "")) for s in steps]
    assert names.index("Restore the pinned references") < names.index("Elastic oracles")
    oracle = (ROOT / "scripts" / "engine" / "oracles" / "oracle.py").read_text(encoding="utf-8")
    # The pins and the check the cache relies on.
    assert '"lucene-core.jar": (' in oracle and "sha256(path.read_bytes())" in oracle
