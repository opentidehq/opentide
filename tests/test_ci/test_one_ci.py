"""One CI for the repository (#801), and the release workflows' triggers.

``ci.yml`` checks the whole repository: the Python jobs, and the Cargo
workspace's (rustfmt, clippy, nextest on three operating systems, rustdoc,
WebAssembly, grammars, npm packs, the licence scan, a fuzz smoke run of every
target, and a dry run of the engine release). A pull request runs the core
gates; the rest is the full set (``tests/test_ci/test_ci_scope.py``). The
checks branch protection requires are the core gates that run on every pull
request, the list ``.github/AGENTS.md`` gives.

Releases: the release train (publish.yml, #840) publishes everything from Run
workflow on development and creates its ``v*`` tag itself; the engine's own
``engine-v*`` series (engine-release.yml) ended there. No workflow runs on a
``v*`` tag, and nothing publishes from a trigger that is not a release.
"""

from __future__ import annotations

import fnmatch
import importlib.util
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from tests.test_ci import ci_matrix

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
GUIDE = ROOT / ".github" / "AGENTS.md"

# What publishes a package, a release or a signed statement about one.
# What publishes a package, a release or a signed statement about one: actions,
# and commands other than `cargo publish` / `npm publish`, which _publishes() below
# reads in every spelling (publish-dry-run.yml rehearses them as dry runs).
PUBLISHING_ACTIONS = re.compile(
    r"pypa/gh-action-pypi-publish|actions/attest-build-provenance|crates-io-auth-action"
)
PUBLISHING_COMMANDS = re.compile(r"release\.py publish|gh release (?:create|upload)")
PUBLISHERS = {"publish.yml"}
# Triggers a release may start from: a tag, a GitHub Release, or a person.
RELEASE_TRIGGERS = {"push", "release", "workflow_dispatch", "repository_dispatch"}
# Expressions an outsider controls: never interpolated into a shell.
UNTRUSTED = re.compile(r"\$\{\{[^}]*(github\.event\.|github\.head_ref|inputs\.)[^}]*\}\}")
SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
# The workflows this item owns hold every checkout to persist-credentials: false.
NO_CREDENTIALS = [
    "ci.yml",
    "codeql.yml",
    "publish.yml",
    "engine-release-build.yml",
    "engine-fuzz.yml",
    "oracle.yml",
]


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # PyYAML reads the key `on` as True.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    return dict(on or {})


def _workflows() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def _runs_on_tag(triggers: dict[str, Any], tag: str) -> bool:
    """Whether a push of `tag`, or a GitHub Release for it, starts the workflow."""
    if "release" in triggers or "create" in triggers:
        return True
    if "push" not in triggers:
        return False
    push = triggers["push"] or {}
    tags = push.get("tags")
    ignored = push.get("tags-ignore")
    if tags is None and ignored is None:
        # A branch filter alone runs on no tag; no filter runs on every tag.
        return "branches" not in push and "branches-ignore" not in push
    if tags is not None:
        return any(fnmatch.fnmatchcase(tag, pattern) for pattern in tags)
    return not any(fnmatch.fnmatchcase(tag, pattern) for pattern in ignored)


@pytest.mark.parametrize("tag", ["v0.24.0", "v1.0.0-rc.1", "v10.2.3"])
def test_no_workflow_runs_on_an_opentide_tag(tag: str) -> None:
    """publish.yml creates the tag with GITHUB_TOKEN, which starts no workflow;
    a tag pushed or a Release published by hand publishes nothing."""
    starting = sorted(
        path.name for path in _workflows() if _runs_on_tag(_triggers(_load(path)), tag)
    )
    assert starting == [], starting


def test_the_tag_check_reads_triggers() -> None:
    assert _runs_on_tag({"push": {"tags": ["v*"]}}, "v1.0.0")
    assert _runs_on_tag({"push": None}, "v1.0.0")
    assert _runs_on_tag({"release": {"types": ["published"]}}, "v1.0.0")
    assert not _runs_on_tag({"push": {"branches": ["development"]}}, "v1.0.0")
    assert not _runs_on_tag({"push": {"tags": ["engine-v*"]}}, "v1.0.0")
    assert _runs_on_tag({"push": {"tags-ignore": ["engine-v*"]}}, "v1.0.0")


def test_the_release_train_runs_from_run_workflow_only() -> None:
    # The engine's release workflow retired into it (#840).
    assert not (WORKFLOWS / "engine-release.yml").exists()
    assert not (WORKFLOWS / "publish-pypi.yml").exists()
    triggers = _triggers(_load(WORKFLOWS / "publish.yml"))
    assert set(triggers) == {"workflow_dispatch", "repository_dispatch"}


def _publish_rules() -> Any:
    """publish-dry-run.yml's own tests parse `cargo publish` and `npm publish` in every
    spelling and tell a dry run apart (tests/test_ci/test_publish_dry_run_workflow.py)."""
    spec = importlib.util.spec_from_file_location(
        "publish_dry_run_rules", ROOT / "tests" / "test_ci" / "test_publish_dry_run_workflow.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _publishes(path: Path) -> bool:
    """Whether a step of the workflow publishes: an action that does, or a command,
    a `cargo publish` / `npm publish` that is not a dry run among them."""
    rules = _publish_rules()
    for job in _load(path)["jobs"].values():
        for step in job.get("steps") or []:
            run = str(step.get("run", ""))
            if PUBLISHING_ACTIONS.search(str(step.get("uses", ""))):
                return True
            if PUBLISHING_COMMANDS.search(run):
                return True
            if any(not rules._is_dry_run(command) for command in rules._publishes(run)):
                return True
    return False


def test_nothing_publishes_from_a_trigger_that_is_not_a_release() -> None:
    publishing = sorted(path.name for path in _workflows() if _publishes(path))
    assert publishing == sorted(PUBLISHERS)
    for name in PUBLISHERS:
        triggers = _triggers(_load(WORKFLOWS / name))
        assert set(triggers) <= RELEASE_TRIGGERS, (name, sorted(triggers))
        push = triggers.get("push") or {}
        # A push publishes only for a tag, never a branch.
        assert "push" not in triggers or set(push) == {"tags"}, (name, push)


def test_the_asset_build_publishes_nothing_and_writes_nothing() -> None:
    path = WORKFLOWS / "engine-release-build.yml"
    workflow = _load(path)
    assert set(_triggers(workflow)) == {"workflow_call"}
    assert workflow["permissions"] == {"contents": "read"}
    for job_id, job in workflow["jobs"].items():
        assert job.get("permissions") in (None, {"contents": "read"}), job_id
    assert not _publishes(path)
    assert "id-token" not in path.read_text(encoding="utf-8")


def test_every_release_job_waits_for_the_guard() -> None:
    """Nothing is built, let alone published, before the guard approved the run."""
    jobs = _load(WORKFLOWS / "publish.yml")["jobs"]
    for job_id, job in jobs.items():
        if job_id != "guard":
            needs = job.get("needs")
            assert "guard" in ([needs] if isinstance(needs, str) else needs or []), job_id
        # A status function would run a job past a failed one unless the job
        # still requires a needed job's success.
        condition = str(job.get("if", ""))
        if re.search(r"always\(\)|!cancelled\(\)|failure\(\)", condition):
            assert re.search(r"needs\.[\w-]+\.result == 'success'", condition), job_id


def test_ci_mints_no_token() -> None:
    assert "id-token" not in CI.read_text(encoding="utf-8")


def test_the_pull_request_dry_run_is_read_only() -> None:
    job = _load(CI)["jobs"]["engine-release-dry-run"]
    assert job["uses"] == "./.github/workflows/engine-release-build.yml"
    assert job["with"] == {"dry-run": True}
    assert job["permissions"] == {"contents": "read"}
    release = _load(WORKFLOWS / "publish.yml")["jobs"]["release-assets"]
    assert release["uses"] == job["uses"]
    assert "dry-run" not in (release.get("with") or {})


@pytest.mark.parametrize("path", _workflows(), ids=lambda path: path.name)
def test_every_action_is_pinned_by_commit(path: Path) -> None:
    for job_id, job in _load(path)["jobs"].items():
        uses = [job["uses"]] if "uses" in job else []
        uses += [str(step["uses"]) for step in job.get("steps") or [] if "uses" in step]
        for ref in uses:
            if ref.startswith("./"):
                continue
            assert SHA_PIN.match(ref), f"{path.name} {job_id}: {ref} is not pinned by commit"


@pytest.mark.parametrize("path", _workflows(), ids=lambda path: path.name)
def test_no_untrusted_expression_in_a_shell(path: Path) -> None:
    for job_id, job in _load(path)["jobs"].items():
        for step in job.get("steps") or []:
            found = UNTRUSTED.search(str(step.get("run", "")))
            assert found is None, f"{path.name} {job_id}: pass {found.group(0)} through env"


@pytest.mark.parametrize("name", NO_CREDENTIALS)
def test_checkouts_keep_no_credentials(name: str) -> None:
    for job_id, job in _load(WORKFLOWS / name)["jobs"].items():
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert (step.get("with") or {}).get("persist-credentials") is False, (
                    f"{name} {job_id}"
                )


def _scope() -> Any:
    """test_ci_scope.py: which ci.yml jobs run on every pull request."""
    spec = importlib.util.spec_from_file_location(
        "ci_scope_rules", ROOT / "tests" / "test_ci" / "test_ci_scope.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _step_runs(job: dict[str, Any]) -> str:
    return "\n".join(str(step.get("run", "")) for step in job.get("steps") or [])


def _ci_jobs() -> dict[str, Any]:
    return _load(CI)["jobs"]


def test_ci_runs_on_every_pull_request_and_on_development() -> None:
    triggers = _triggers(_load(CI))
    assert triggers["pull_request"] is None, "every base branch, no path filter"
    assert "development" in triggers["push"]["branches"]
    # The full set, nightly.
    assert "schedule" in triggers


@pytest.mark.parametrize("name", ["ci.yml", "codeql.yml", "oracle.yml"])
def test_the_integration_branch_gets_ci_after_each_merge(name: str) -> None:
    """The Unified Core PRs merge into integration/unified-core before development."""
    branches = _triggers(_load(WORKFLOWS / name))["push"]["branches"]
    assert {"development", "integration/unified-core"} <= set(branches), name


# The engine-test job notes the checkout before the tests and after them (#931).
TREE_BEFORE = 'git status --porcelain --untracked-files=all > "$RUNNER_TEMP/tree-before"'
TREE_AFTER = 'git status --porcelain --untracked-files=all > "$RUNNER_TEMP/tree-after"'


# A shard names its packages (matrix.packages, read into an array).
NEXTEST = 'cargo nextest run --locked --profile ci "${selected[@]}" "${filter[@]}"'
DOCTESTS = 'cargo test --locked --doc "${selected[@]}"'


def _runs_command(line: str, command: str) -> bool:
    """The line is the command, or the command and its options (a shard's)."""
    line = line.strip()
    return line == command


@pytest.mark.parametrize(
    ("job", "command"),
    [
        ("engine", "cargo fmt --all --check"),
        ("engine", "cargo clippy --workspace --all-targets --locked -- -D warnings"),
        ("engine", "target/debug/xtask check-layers"),
        ("engine", "cargo doc --no-deps --workspace --locked"),
        ("engine-test-part", NEXTEST),
        ("engine-test-part", DOCTESTS),
        # The tests leave the checkout as they found it (#931).
        ("engine-test-part", TREE_BEFORE),
        ("engine-test-part", TREE_AFTER),
        ("engine-wasm", "bash scripts/engine/build-wasm.sh"),
        ("engine-wasm", "node scripts/engine/check-npm-packs.mjs"),
        (
            "engine-package",
            "bash scripts/engine/license-scan.sh --product target/package/opentide-cli-*.crate",
        ),
        ("grammars", "bash scripts/engine/check-grammars.sh"),
        ("fuzz-smoke", 'bash scripts/engine/fuzz.sh "${target}" 60'),
        (
            "engine-release-consumers",
            "node scripts/engine/check-vscode-extension.mjs"
            ' vscode-extension release-assets "$(python3 scripts/engine/release.py tag)"',
        ),
    ],
)
def test_ci_runs_the_rust_gates(job: str, command: str) -> None:
    """Each gate runs, and nothing lets it pass without running or while failing."""
    spec = _ci_jobs()[job]
    steps = [
        step
        for step in spec.get("steps") or []
        if any(_runs_command(line, command) for line in str(step.get("run", "")).splitlines())
    ]
    assert len(steps) == 1, (job, command)
    step = steps[0]
    assert "continue-on-error" not in step, (job, command)
    assert "continue-on-error" not in spec, job
    # Only the scope's condition: the core gates have none, the full set's
    # jobs exactly theirs (test_ci_scope.py).
    assert spec.get("if") == _scope().expected_condition(job), job
    # The doctests run on Linux, each shard its packages'; nothing else is
    # conditional.
    allowed = {("engine-test-part", DOCTESTS): "runner.os == 'Linux'"}
    assert step.get("if") == allowed.get((job, command)), (job, command, step.get("if"))
    run = str(step["run"])
    assert not re.search(r"\|\|\s*(?:true|:)\b", run), (job, command)


def test_ci_fails_when_the_rust_tests_leave_a_file_in_the_checkout() -> None:
    """The checkout is noted before the tests and compared after them; a
    difference fails the job (#931)."""
    jobs = _ci_jobs()
    steps = [str(step.get("run", "")) for step in jobs["engine-test-part"].get("steps") or []]

    def index(command: str) -> int:
        found = [
            i
            for i, run in enumerate(steps)
            if any(_runs_command(line, command) for line in run.splitlines())
        ]
        assert len(found) == 1, command
        return found[0]

    before = index(TREE_BEFORE)
    nextest = index(NEXTEST)
    doctests = index(DOCTESTS)
    guard = index(TREE_AFTER)
    assert before < nextest < doctests < guard
    lines = [line.strip() for line in steps[guard].splitlines()]
    assert 'if ! diff -u "$RUNNER_TEMP/tree-before" "$RUNNER_TEMP/tree-after"; then' in lines
    assert "exit 1" in lines


def test_every_cargo_job_denies_warnings() -> None:
    """A compiler warning fails every ci.yml step that builds with cargo, as in
    language-server's CI (engine-ci.yml set it workflow-wide): the workflow's,
    job's or step's environment sets ``RUSTFLAGS=-Dwarnings``. A step may set it
    alone where the job's environment is a Rust cache's key (``lint`` reads the
    binding's cache, built without it). The nightly fuzz build is left out: its
    lints are a nightly's, not the pinned release's."""
    workflow = _load(CI)
    checked = []
    for job_id, job in workflow["jobs"].items():
        if "uses" in job or job_id == "fuzz-smoke":
            continue
        for step in job.get("steps") or []:
            if not re.search(r"\bcargo (?!\+)", str(step.get("run", ""))):
                continue
            env = {
                **(workflow.get("env") or {}),
                **(job.get("env") or {}),
                **(step.get("env") or {}),
            }
            assert env.get("RUSTFLAGS") == "-Dwarnings", (job_id, step.get("name"))
            checked.append(job_id)
    assert {"engine", "engine-test-part", "engine-package", "bench", "clients", "lint"} <= set(
        checked
    )


def test_the_oracles_are_required() -> None:
    """A reference the oracle job cannot run is a red build, not a skip."""
    oracle = _load(WORKFLOWS / "oracle.yml")
    assert oracle["env"]["OPENTIDE_ORACLE_REQUIRED"] == "1"


def test_rustdoc_denies_warnings() -> None:
    steps = _ci_jobs()["engine"]["steps"]
    doc = next(step for step in steps if "cargo doc" in str(step.get("run", "")))
    assert doc["env"]["RUSTDOCFLAGS"] == "-D warnings"


def test_nextest_runs_on_three_operating_systems() -> None:
    jobs = _ci_jobs()
    assert jobs["engine-test"]["strategy"]["matrix"]["os"] == [
        "ubuntu-latest",
        "macos-latest",
        "windows-latest",
    ]
    for scope, systems in (
        # The full set: three operating systems.
        ("full", ["ubuntu-latest", "macos-latest", "windows-latest"]),
        # A pull request: Linux, in the same shards (the gathering job reports
        # macOS's and Windows's required checks).
        ("pull", ["ubuntu-latest"]),
    ):
        shards: dict[str, list[tuple[int, int]]] = {}
        for cell in ci_matrix.cells(jobs["engine-test-part"], scope):
            shards.setdefault(cell["os"], []).append((int(cell["shard"]), int(cell["shards"])))
        assert list(shards) == systems, scope
        for os_name, cells in shards.items():
            # Every partition of each OS runs, once: a missing shard would skip its tests.
            count = cells[0][1]
            assert sorted(cells) == [(n, count) for n in range(1, count + 1)], os_name
    full = ci_matrix.cells(jobs["engine-test-part"], "full")
    pull = ci_matrix.cells(jobs["engine-test-part"], "pull")
    assert [c for c in full if c["os"] == "ubuntu-latest"] == pull
    # Linux by package (test_ci_scope.py holds the packages to the workspace's
    # members, once each); macOS and Windows whole.
    for cell in full:
        whole = cell["os"] != "ubuntu-latest"
        assert (cell["packages"] == "--workspace") is whole, cell
    for step in jobs["engine-test-part"]["steps"]:
        run = str(step.get("run", ""))
        if NEXTEST in run or DOCTESTS in run:
            assert step["env"]["PACKAGES"] == "${{ matrix.packages }}"
            assert 'read -ra selected <<< "${PACKAGES}"' in run
            assert "--partition" not in run


def test_the_fuzz_smoke_covers_every_target() -> None:
    targets = sorted(path.stem for path in (ROOT / "fuzz" / "fuzz_targets").glob("*.rs"))
    assert targets
    groups = _ci_jobs()["fuzz-smoke"]["strategy"]["matrix"]["targets"]
    listed = sorted(target for group in groups for target in group.split())
    assert listed == targets


def test_language_servers_engine_ci_is_folded_in() -> None:
    assert not (WORKFLOWS / "engine-ci.yml").exists()
    assert not (ROOT / ".github" / "engine-workflows").exists()


def _check_names(path: Path) -> list[tuple[str, bool]]:
    """Each check run a pull request gets from the workflow, with whether it
    can fail the pull request (a job with continue-on-error cannot)."""
    workflow = _load(path)
    names: list[tuple[str, bool]] = []
    for job_id, job in workflow["jobs"].items():
        name = str(job.get("name", job_id))
        gating = job.get("continue-on-error") is not True
        if "uses" in job:
            called = _load(ROOT / job["uses"].removeprefix("./"))
            names += [(f"{name} / {sub}", gating) for sub, _ in _check_names_of(called)]
            continue
        names += [(cell, gating) for cell in _expand(name, job)]
    return names


def _check_names_of(workflow: dict[str, Any]) -> list[tuple[str, bool]]:
    return [
        (cell, job.get("continue-on-error") is not True)
        for job_id, job in workflow["jobs"].items()
        for cell in _expand(str(job.get("name", job_id)), job)
    ]


def _expand(name: str, job: dict[str, Any]) -> list[str]:
    """The check names of a job's cells (the full set's: a superset)."""
    pattern = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
    return [
        pattern.sub(lambda m, cell=cell: cell[m.group(1)], name)
        for cell in ci_matrix.cells(job, "full")
    ]


def _documented_checks() -> list[str]:
    text = GUIDE.read_text(encoding="utf-8")
    block = re.search(r"<!-- required-checks -->\n```text\n(.*?)```", text, re.DOTALL)
    assert block is not None, ".github/AGENTS.md lists the required checks"
    return block.group(1).splitlines()


def _every_pull_request(jobs: dict[str, Any], job_id: str) -> bool:
    """Whether the job runs on every pull request: no `if`, and every job it
    needs runs on every pull request too (a skipped one skips it)."""
    job = jobs[job_id]
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else needs
    if job.get("if") == _scope().GATHER:
        # It runs whatever its parts did, skipped ones included, and decides
        # (test_ci_scope.py, CI_GATHER): its check starts on every pull request.
        return True
    return "if" not in job and all(_every_pull_request(jobs, need) for need in needs)


def _gathered(jobs: dict[str, Any]) -> set[str]:
    """The jobs a gathering job stands for: its check is the required one."""
    gather = _scope().GATHER
    found: set[str] = set()
    for job in jobs.values():
        if job.get("if") == gather:
            needs = job.get("needs") or []
            found |= {needs} if isinstance(needs, str) else set(needs)
    # A path-scoped gathering job also needs `changes`, which is no part of it.
    return found - {"changes"}


def _required_names(path: Path) -> list[str]:
    """The gating checks of the jobs that run on every pull request."""
    workflow = _load(path)
    jobs = workflow["jobs"]
    names: list[str] = []
    gathered = _gathered(jobs)
    for job_id, job in jobs.items():
        if not _every_pull_request(jobs, job_id) or job.get("continue-on-error") is True:
            continue
        if job_id in gathered:
            continue
        names += _expand(str(job.get("name", job_id)), job)
    return names


def test_the_required_checks_are_the_gates_of_every_pull_request() -> None:
    """A required check must start on every pull request (one that never
    starts blocks the merge), so the full set's jobs are not required."""
    expected = [name for path in (CI, WORKFLOWS / "codeql.yml") for name in _required_names(path)]
    assert len(expected) == len(set(expected)), "check names are unique"
    assert sorted(_documented_checks()) == sorted(expected)
    gating = {name for name, gating in _check_names(CI) if gating}
    assert set(_required_names(CI)) <= gating
    # The full set's jobs do run as checks, just not on every pull request.
    assert {"Test (3.11)", "Fuzz smoke (cli)", "Engine release (dry run) / SBOMs"} <= gating
    assert not {"Test (3.11)", "Fuzz smoke (cli)"} & set(_documented_checks())


def test_the_informational_jobs_are_not_required() -> None:
    informational = [name for name, gating in _check_names(CI) if not gating]
    assert sorted(informational) == ["Benchmarks (informational)", "LSP clients (informational)"]
    for name in informational:
        assert name not in _documented_checks()


def test_only_report_uploads_may_fail_without_failing_their_job() -> None:
    """A report upload is for reading, not a gate.

    When GitHub's artifact service is down, ``actions/upload-artifact`` fails
    after its retries, and that must not fail a job whose checks passed. No
    other step in ci.yml may set continue-on-error. The one upload a gate
    reads, golden compare's unused ledger entries (the gather finds the stale
    ones in them), fails its part instead.
    """
    gate_inputs = {("golden-compare-part", "Upload the unused ledger entries")}
    uploads = 0
    for job_id, spec in _ci_jobs().items():
        for step in spec.get("steps") or []:
            if (job_id, step.get("name")) in gate_inputs:
                assert "continue-on-error" not in step, (job_id, step.get("name"))
            elif str(step.get("uses", "")).startswith("actions/upload-artifact@"):
                uploads += 1
                assert step.get("continue-on-error") is True, (job_id, step.get("name"))
            else:
                label = step.get("name") or step.get("run")
                assert "continue-on-error" not in step, (job_id, label)
    assert uploads >= 7


def test_the_facade_semver_check_names_the_crate_and_isolates_the_baseline() -> None:
    """The facade is ``publish = false`` and its name is also held by a placeholder.

    cargo-semver-checks skips a crate with ``publish = false`` unless ``-p``
    names it (and exits 0, so the check would pass without running), and
    ``--baseline-rev`` searches the whole tree, where
    ``publishing/placeholders/crates/opentide`` is a second ``opentide``.
    """
    steps = _ci_jobs()["facade"]["steps"]
    run = next(str(step["run"]) for step in steps if "semver-checks" in str(step.get("run", "")))
    command = " ".join(run.replace("\\\n", " ").split())
    assert "cargo semver-checks -p opentide " in command
    assert "--baseline-root" in command
    assert "/crates/opentide" in command.split("--baseline-root", 1)[1]
    assert "--baseline-rev" not in command
