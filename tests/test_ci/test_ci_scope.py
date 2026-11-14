"""What runs on a pull request, and what only nightly.

The maintainer's rules (2026-11-14), held here:

- **The gate**, on every pull request and every push to a base branch, on
  Linux: Lint (ruff, ty, actionlint, the sdist), Engine lint (fmt, clippy,
  rustdoc, the layers, the generated artifacts), the engine tests in four
  shards and their gathering check, Python 3.14 with its coverage gate, E2E in
  four shards and cargo deny, plus CodeQL (codeql.yml). Nothing else runs on a
  pull request. The gate's jobs carry no ``if``: they are the required checks
  (a required check that never starts blocks the merge).
- **The nightly set**, nightly and on Run workflow only, never on a pull
  request or a push, so it never blocks a merge: the platform and packaging
  matrix (macOS and Windows engine tests, the wheels and npm tarballs, the
  conformance suite, the release dry run, the WASI build, WebAssembly, fuzz
  smoke and the rest), and the other workflows (coverage, benchmarks, schema,
  the vendor-parser oracles, docs, the publish dry run). Each such job's
  ``if`` is exactly ``NIGHTLY_SET``; the other workflows have no other
  trigger. There is no ``full-ci`` label.
- **The Python oracle's comparisons left CI** (golden compare and check, the
  corpora, the MCP replay, the payload, config, validate and lint diffs,
  codegen's oracle comparisons): no workflow runs them
  (test_golden_workflow.py).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
INTEGRATION = "integration/unified-core"

# The condition of a job in the nightly set (tests/test_ci/ci_matrix.py too).
NIGHTLY_SET = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
# Kept for the readers of the old name (test_one_ci.py's expected_condition).
FULL_SET = NIGHTLY_SET

# ci.yml's gate: no `if`, and only gate jobs needed.
CI_GATE = {"lint", "engine", "engine-test-part", "deny", "test", "cli-e2e"}
# Jobs that gather the parts of a gate under the required check's name: `if`
# is exactly GATHER, so a failed part fails it instead of skipping it (a
# skipped required check passes), and it fails unless its parts succeeded.
GATHER = "${{ !cancelled() }}"
CI_GATHER = {"engine-test": "engine-test-part"}
# ci.yml's jobs in the nightly set.
CI_NIGHTLY = {
    "facade",
    "node",
    "npm-install",
    "packages",
    "conformance",
    "wasi",
    "engine-wasm",
    "engine-package",
    "grammars",
    "textmate",
    "elastic-sweep",
    "fuzz-smoke",
    "engine-release-dry-run",
    "clients",
    "bench",
    "test-full",
    "cli-e2e-full",
    "gitlab-ci-lint",
    "cli-windows-smoke",
}
# Jobs that run when the job they need does, and only then.
CI_DEPENDENT = {"engine-release-consumers": "engine-release-dry-run"}
# The other workflows of the nightly set: their only triggers.
OTHER_NIGHTLY = [
    "coverage.yml",
    "bench.yml",
    "schema.yml",
    "oracle.yml",
    "docs.yml",
    "publish-dry-run.yml",
]
# What a pull request runs: ci.yml's gate, CodeQL, and the stack comment (a
# comment, not a check).
ON_PULL_REQUESTS = {"ci.yml", "codeql.yml", "stack-comment.yml"}


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # PyYAML reads the key `on` as True.
    return dict(workflow.get("on", workflow.get(True)) or {})


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def expected_condition(job_id: str) -> str | None:
    """The `if` ci.yml's job must have (None: no `if`)."""
    if job_id in CI_NIGHTLY:
        return NIGHTLY_SET
    if job_id in CI_GATHER:
        return GATHER
    return None


def _ci_jobs() -> dict[str, Any]:
    return _load(CI)["jobs"]


def test_every_ci_job_has_one_scope() -> None:
    scopes = [CI_GATE, CI_NIGHTLY, set(CI_DEPENDENT), set(CI_GATHER)]
    every = [job for scope in scopes for job in scope]
    assert len(every) == len(set(every)), "a job is in two scopes"
    assert set(_ci_jobs()) == set(every)


@pytest.mark.parametrize("job_id", sorted(CI_GATE))
def test_the_gate_runs_on_every_pull_request(job_id: str) -> None:
    job = _ci_jobs()[job_id]
    assert "if" not in job, f"{job_id} is in the gate: it runs on every pull request"
    assert "continue-on-error" not in job, job_id
    assert set(_needs(job)) <= CI_GATE, (job_id, _needs(job))
    assert job.get("runs-on") in ("ubuntu-latest", "${{ matrix.os }}"), job_id


@pytest.mark.parametrize("job_id", sorted(CI_NIGHTLY))
def test_the_rest_runs_nightly_and_by_hand_only(job_id: str) -> None:
    job = _ci_jobs()[job_id]
    assert job.get("if") == NIGHTLY_SET, job_id
    assert not _needs(job), f"{job_id} needs nothing: no path filter decides it"


@pytest.mark.parametrize(("job_id", "after"), sorted(CI_DEPENDENT.items()))
def test_a_dependent_job_runs_with_the_job_it_needs(job_id: str, after: str) -> None:
    job = _ci_jobs()[job_id]
    # No `if`: the implicit success() skips it whenever `after` is skipped.
    assert "if" not in job, job_id
    assert _needs(job) == [after]


@pytest.mark.parametrize(("job_id", "parts"), sorted(CI_GATHER.items()))
def test_a_gathering_job_fails_unless_every_part_passed(job_id: str, parts: str) -> None:
    job = _ci_jobs()[job_id]
    assert job.get("if") == GATHER, job_id
    assert _needs(job) == [parts], job_id
    (step,) = job["steps"]
    for result, passes in (("success", True), ("failure", False), ("cancelled", False)):
        done = subprocess.run(
            ["bash", "-ec", step["run"]],
            env={**os.environ, "RESULT": result},
            capture_output=True,
            check=False,
        )
        assert (done.returncode == 0) is passes, result


def test_the_gate_tests_linux_and_the_nightly_set_every_os() -> None:
    from tests.test_ci import ci_matrix

    jobs = _ci_jobs()
    for job_id in ("engine-test-part", "engine-test"):
        pull = {cell["os"] for cell in ci_matrix.cells(jobs[job_id], "pull")}
        full = {cell["os"] for cell in ci_matrix.cells(jobs[job_id], "full")}
        assert pull == {"ubuntu-latest"}, job_id
        assert full == {"ubuntu-latest", "macos-latest", "windows-latest"}, job_id
    # Each OS runs the same shards in the nightly set: the Linux packages.
    full = ci_matrix.cells(jobs["engine-test-part"], "full")
    linux = [
        (c["shard"], c["packages"], c.get("goldens")) for c in full if c["os"] == "ubuntu-latest"
    ]
    for os_name in ("macos-latest", "windows-latest"):
        cells = [(c["shard"], c["packages"], c.get("goldens")) for c in full if c["os"] == os_name]
        assert cells == linux, os_name


def test_python_runs_the_newest_on_a_pull_request_and_every_version_nightly() -> None:
    jobs = _ci_jobs()
    gate = jobs["test"]["strategy"]["matrix"]["python-version"]
    nightly = jobs["test-full"]["strategy"]["matrix"]["python-version"]
    assert gate == ["3.14"]
    assert sorted(gate + nightly, key=lambda v: tuple(map(int, v.split(".")))) == [
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
    # No cell of the gate starts only to skip its steps.
    assert "RUNS" not in json.dumps(jobs["test"])


def test_ci_runs_on_every_pull_request_push_nightly_and_on_demand() -> None:
    workflow = _load(CI)
    triggers = _triggers(workflow)
    assert triggers["pull_request"] is None, "every base branch, no path filter"
    assert {"development", INTEGRATION} <= set(triggers["push"]["branches"])
    assert "workflow_dispatch" in triggers
    assert len(triggers["schedule"]) == 1
    # The nightly run and a push to development must not cancel each other.
    assert "github.event_name" in workflow["concurrency"]["group"]
    assert "full-ci" not in CI.read_text(encoding="utf-8").replace("no `full-ci` label", "")


@pytest.mark.parametrize("name", OTHER_NIGHTLY)
def test_the_other_workflows_run_nightly_and_by_hand_only(name: str) -> None:
    workflow = _load(WORKFLOWS / name)
    triggers = _triggers(workflow)
    assert set(triggers) == {"schedule", "workflow_dispatch"}, (name, set(triggers))
    assert len(triggers["schedule"]) == 1, name
    for job_id, job in workflow["jobs"].items():
        assert "full-ci" not in str(job.get("if", "")), (name, job_id)
        assert "needs.changes" not in str(job.get("if", "")), (name, job_id)


def test_only_the_gate_and_codeql_run_on_a_pull_request() -> None:
    on_pull_requests = {
        path.name
        for path in sorted(WORKFLOWS.glob("*.yml"))
        if "pull_request" in _triggers(_load(path))
    }
    assert on_pull_requests == ON_PULL_REQUESTS
    for path in sorted(WORKFLOWS.glob("*.yml")):
        assert "full-ci" not in "\n".join(
            str(job.get("if", "")) for job in (_load(path).get("jobs") or {}).values()
        ), path.name


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


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "--allow-empty", "-q", "-m", message)


def _pull_request(tmp_path: Path, change: dict[str, str | None]) -> Path:
    """A repository whose HEAD is a pull request's merge commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "base")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _commit(repo, "base")
    _git(repo, "switch", "-q", "-c", "topic")
    for path, content in change.items():
        if content is None:
            _git(repo, "rm", "-q", path)
        else:
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(content, encoding="utf-8")
    _commit(repo, "topic")
    _git(repo, "switch", "-q", "base")
    (repo / "README.md").write_text("base moved on\n", encoding="utf-8")
    _commit(repo, "base moved on")
    _git(repo, "merge", "-q", "--no-ff", "--no-edit", "topic")
    return repo


def _pytest_markers(job_id: str) -> list[str]:
    """The ``-m`` expression of each pytest step of ci.yml's *job_id*."""
    markers = []
    for step in _ci_jobs()[job_id]["steps"]:
        run = str(step.get("run", ""))
        if "pytest" in run:
            words = shlex.split(run.replace("\\\n", " "))
            markers.append(words[words.index("-m") + 1])
    return markers


def test_the_full_set_e2e_tests_run_nightly_only() -> None:
    """A test marked ``full_set`` (a wheel built per test, UC-4.5c, #835)
    runs in ``cli-e2e-full``, nightly, never on a pull request: ``cli-e2e`` leaves
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


# ---- CodeQL, actionlint and run names ----------------------------------------


def _codeql_scope(repo: Path, tmp_path: Path, language: str, event: str) -> str:
    workflow = _load(WORKFLOWS / "codeql.yml")
    step = next(s for s in workflow["jobs"]["analyze"]["steps"] if s.get("id") == "scope")
    output = tmp_path / "codeql_output"
    output.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "EVENT_NAME": event,
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
    repo = _pull_request(tmp_path, change)
    assert _codeql_scope(repo, tmp_path, "python", "pull_request") == f"analyse={python}"
    assert _codeql_scope(repo, tmp_path, "actions", "pull_request") == f"analyse={actions}"
    # A push and the weekly run: every language.
    for event in ("push", "schedule"):
        assert _codeql_scope(repo, tmp_path, "python", event) == "analyse=true"


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
    """A failure on a base branch is visible as the merge it came from."""
    run_name = str(_load(CI)["run-name"])
    assert "github.event.head_commit.message" in run_name
    assert "github.event_name == 'push'" in run_name


def test_the_pinned_elastic_references_are_cached_and_checked() -> None:
    """Lucene's jars and the Elastic grammars come from Maven Central and
    GitHub: cached under oracle.py's pins (Maven answered HTTP 429 on #1041),
    saved by the scheduled run only, each file's SHA-256 checked by oracle.py."""
    steps = _load(WORKFLOWS / "oracle.yml")["jobs"]["elastic"]["steps"]
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


def test_a_pull_request_builds_the_sdist_and_the_nightly_set_the_wheel_from_it() -> None:
    """The wheel from the sdist took 4 to 6 minutes of Lint in a temporary
    directory sccache cannot reuse; the nightly set still builds it (and
    `packages` every installable wheel). A pull request checks the sdist."""
    steps = {step.get("name"): step for step in _ci_jobs()["lint"]["steps"]}
    assert steps["Build the sdist"]["run"] == "uv build --sdist"
    assert steps["Twine check"]["run"] == "uvx twine check dist/*"
    for name in ("Build the sdist", "Twine check"):
        assert "if" not in steps[name], name
    assert steps["Build the wheel from the sdist"]["if"] == NIGHTLY_SET


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
    # The shard of command_goldens' slowest groups builds shard 1's packages
    # again (test_the_slowest_goldens_run_apart_from_the_rest_of_their_shard).
    return [
        ci_matrix.selection(cell["packages"])[0]
        for cell in sorted(cells, key=lambda c: int(c["shard"]))
        if cell.get("goldens") != "heavy"
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


# command_goldens' slowest groups (a minute or more each) run in a Linux shard
# of their own, out of shard 1's (#841): the same packages, features and tests,
# split by a nextest filter and its complement.
HEAVY_GOLDENS = (
    "binary_id(opentide-cli::command_goldens) & "
    "test(/^(generate_phase|new_threat|new_objective|new_rule|setup)_cases_are_the_oracles$/)"
)


def _nextest_step() -> dict[str, Any]:
    (step,) = [
        s
        for s in _ci_jobs()["engine-test-part"]["steps"]
        if s.get("name") == "cargo nextest (profile ci)"
    ]
    return step


def test_the_slowest_goldens_run_apart_from_the_rest_of_their_shard() -> None:
    from tests.test_ci import ci_matrix

    cells = ci_matrix.cells(_ci_jobs()["engine-test-part"], "pull")
    (rest,) = [c for c in cells if c.get("goldens") == "rest"]
    (heavy,) = [c for c in cells if c.get("goldens") == "heavy"]
    # The same build: packages and features, so the tests run as in shard 1.
    assert heavy["packages"] == rest["packages"]
    assert "opentide-cli" in ci_matrix.selection(rest["packages"])[0]
    assert {c.get("goldens") for c in cells} == {"rest", "heavy", None}
    step = _nextest_step()
    assert step["env"]["HEAVY_GOLDENS"] == HEAVY_GOLDENS
    run = step["run"]
    # A filter and its complement: every test of shard 1 runs in exactly one.
    assert 'rest) filters+=("not (${HEAVY_GOLDENS})")' in run
    assert 'filters+=("${HEAVY_GOLDENS}")' in run
    assert "selected+=(--test command_goldens)" in run
    # Each named group is a test of command_goldens.
    source = (ROOT / "crates/opentide-cli/tests/command_goldens.rs").read_text("utf-8")
    group = re.search(r"\^\((.*)\)_cases_are_the_oracles\$", HEAVY_GOLDENS)
    assert group
    for name in group.group(1).split("|"):
        assert f"fn {name}_cases_are_the_oracles()" in source, name
    # Shard 1 runs the doctests of the packages both build.
    (doctests,) = [
        s for s in _ci_jobs()["engine-test-part"]["steps"] if s.get("name") == "doctests"
    ]
    assert "matrix.goldens != 'heavy'" in doctests["if"]


@pytest.mark.parametrize(
    ("goldens", "expected"),
    [
        ("rest", f"-E not ({HEAVY_GOLDENS})"),
        ("heavy", f"--test command_goldens -E {HEAVY_GOLDENS}"),
        ("", ""),
    ],
)
def test_the_shard_filters_the_slowest_goldens(tmp_path: Path, goldens: str, expected: str) -> None:
    """The step's own shell, with a `cargo` that prints its arguments."""
    step = _nextest_step()
    cargo = tmp_path / "cargo"
    cargo.write_text('#!/bin/sh\nshift 5\necho "$@"\n', encoding="utf-8")
    cargo.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        "PACKAGES": "-p opentide-cli -p opentide-kql",
        "UI": "true",
        "GOLDENS": goldens,
        "HEAVY_GOLDENS": step["env"]["HEAVY_GOLDENS"],
    }
    out = subprocess.run(
        ["bash", "-e", "-c", step["run"]], env=env, capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == f"-p opentide-cli -p opentide-kql {expected}".strip()


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


def test_the_compile_fail_cases_wait_for_the_nightly_set_otherwise(tmp_path: Path) -> None:
    assert _ui_decision(tmp_path, NOT_UI_INPUTS, "false") == "run=false"


def test_the_compile_fail_cases_run_in_the_nightly_set(tmp_path: Path) -> None:
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
    assert step["env"]["FULL_SET"] == "${{ " + NIGHTLY_SET + " }}"
    (nextest,) = [s for s in job["steps"] if "cargo nextest run" in str(s.get("run", ""))]
    assert nextest["env"]["UI"] == "${{ steps.ui.outputs.run }}"
    assert "filters+=('not binary_id(opentide-schema::ui)')" in nextest["run"]
    condition = 'if [[ "${UI}" != true && " ${PACKAGES} " == *" -p opentide-schema "* ]]; then'
    assert condition in nextest["run"]
    owners = [
        cell
        for cell in ci_matrix.cells(job, "pull")
        if "opentide-schema" in ci_matrix.selection(cell["packages"])[0]
    ]
    assert len(owners) == 1 and f" {owners[0]['packages']} ".count(" -p opentide-schema ") == 1
