"""The Rust caches of the repository's workflows: one strategy.

GitHub keeps 10 GB of Actions caches per repository and evicts the oldest
beyond that, so a tree two jobs build is cached once: one job saves it, the
others read it (``save-if: false``). ci.yml names every cache with a
``shared-key`` (and a ``key`` where one job builds several trees, per OS or
per target), and each name has exactly one producer.

Swatinem/rust-cache hashes the job's ``CARGO*``, ``CC*``, ``CFLAGS*``,
``CXX*``, ``CMAKE*`` and ``RUST*`` environment variables, and the runner's
toolchain, into the key (the "Environment considered" list in its log), so a
reader whose environment or runner differs from the producer's computes another
key and never restores anything. Its key does not hold the matrix: two cells of
one job on the same runner share a cache unless ``key`` tells them apart.

A release builds from nothing: publish.yml restores no cache, and the
asset build it shares with ci.yml's dry run (engine-release-build.yml) restores
one only under ``inputs.dry-run``.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import yaml
from tests.test_ci import ci_matrix

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
RUST_CACHE = "Swatinem/rust-cache@"
# The variables rust-cache hashes into its key, by prefix.
KEY_ENV_PREFIXES = ("CARGO", "CC", "CFLAGS", "CXX", "CMAKE", "RUST")
DEFAULT_WORKSPACES = ". -> target"
MATRIX = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
# `save-if: ${{ matrix.<axis> == env.<NAME> }}`: one cell of the matrix saves
# (on the events the condition's other terms allow).
SAVE_IF_CELL = re.compile(
    r"\$\{\{\s*(?:github\.event_name == 'push' && )?"
    r"matrix\.([A-Za-z0-9_-]+)\s*==\s*env\.([A-Za-z0-9_]+)\s*\}\}"
)
# Caches are saved from pushes to the base branches only (#841): a pull
# request's cache serves that pull request alone, and its gigabytes evicted
# the base branches' caches every other pull request reads.
PUSH_ONLY = "github.event_name == 'push'"
# The nightly and pushes to development, the default branch whose caches every
# branch reads: the families no pull request needs a copy of on its own base.
DEVELOPMENT_ONLY = "(github.event_name == 'schedule' || github.ref == 'refs/heads/development')"

# The engine's debug tree: engine-test's Linux cell saves it, the Linux jobs
# that build a subset of it read it.
ENGINE_DEBUG_PRODUCER = ("ci.yml", "engine-test-part", "ubuntu-latest")
ENGINE_DEBUG_READERS = (("ci.yml", "clients"), ("ci.yml", "elastic-sweep"))
# The Python jobs' `uv sync` build of the binding: test's 3.14 cell saves it.
PYTHON_PRODUCER = ("ci.yml", "test")
PYTHON_READERS = (
    ("ci.yml", "lint"),
    ("ci.yml", "test-full"),
    ("ci.yml", "cli-e2e"),
    ("ci.yml", "gitlab-ci-lint"),
)


class RustCache(NamedTuple):
    workflow: str
    job: str
    runs_on: str
    shared_key: str | None
    key: str | None
    saves: bool
    condition: str | None
    workspaces: str
    key_env: dict[str, str]


def _env(block: dict[str, Any]) -> dict[str, str]:
    return {str(name): str(value) for name, value in (block.get("env") or {}).items()}


def _cells(job: dict[str, Any]) -> list[dict[str, str]]:
    """The job's matrix cells in the full set (a superset of a pull request's)."""
    return ci_matrix.cells(job, "full")


def _resolve(value: Any, cell: dict[str, str]) -> str | None:
    if value is None:
        return None
    return MATRIX.sub(lambda m: cell.get(m.group(1), m.group(0)), str(value))


def _saves(save_if: Any, cell: dict[str, str], env: dict[str, str]) -> bool:
    """Whether a cell saves: `save-if` defaults to true, and an expression saves
    on some events, except the one-cell comparison it can resolve."""
    if save_if is False:
        return False
    match = SAVE_IF_CELL.fullmatch(str(save_if).strip())
    if match:
        return cell.get(match.group(1)) == env.get(match.group(2))
    return True


def _rust_caches() -> list[RustCache]:
    caches: list[RustCache] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (workflow.get("jobs") or {}).items():
            steps = [
                s for s in job.get("steps") or [] if str(s.get("uses", "")).startswith(RUST_CACHE)
            ]
            assert len(steps) <= 1, f"{path.name} {job_id}: two Rust caches"
            for step in steps:
                inputs = step.get("with") or {}
                env = {**_env(workflow), **_env(job), **_env(step)}
                for cell in _cells(job):
                    caches.append(
                        RustCache(
                            workflow=path.name,
                            job=job_id,
                            runs_on=str(_resolve(job.get("runs-on"), cell)),
                            shared_key=_resolve(inputs.get("shared-key"), cell),
                            key=_resolve(inputs.get("key"), cell),
                            saves=_saves(inputs.get("save-if", True), cell, env),
                            condition=step.get("if"),
                            workspaces=str(inputs.get("workspaces", DEFAULT_WORKSPACES)),
                            key_env={
                                k: v for k, v in env.items() if k.startswith(KEY_ENV_PREFIXES)
                            },
                        )
                    )
    return caches


def _in(workflow: str) -> list[RustCache]:
    return [cache for cache in _rust_caches() if cache.workflow == workflow]


def _name(cache: RustCache) -> tuple[str | None, str | None]:
    return (cache.shared_key, cache.key)


def test_every_ci_cache_is_named() -> None:
    caches = _in("ci.yml")
    assert caches
    for cache in caches:
        assert cache.shared_key, f"ci.yml {cache.job}: name its cache with shared-key"
        # A matrix value must resolve; a step output (the nightly's version) names
        # the toolchain at run time.
        assert "${{ matrix." not in (cache.key or ""), f"ci.yml {cache.job}: key {cache.key}"


def test_every_cache_name_has_one_producer_with_the_readers_key() -> None:
    groups: dict[tuple[str | None, str | None], list[RustCache]] = defaultdict(list)
    for cache in _rust_caches():
        if cache.shared_key:
            groups[_name(cache)].append(cache)
    assert groups
    for name, caches in groups.items():
        producers = {(c.workflow, c.job) for c in caches if c.saves}
        assert len(producers) == 1, f"cache {name}: one job saves it, not {sorted(producers)}"
        producer = next(c for c in caches if c.saves)
        for cache in caches:
            where = f"cache {name}: {cache.workflow} {cache.job}"
            assert cache.runs_on == producer.runs_on, where
            assert cache.workspaces == producer.workspaces, where
            # Otherwise rust-cache computes another key and the reader restores nothing.
            assert cache.key_env == producer.key_env, (
                f"{where} has {cache.key_env}, its producer "
                f"{producer.workflow} {producer.job} {producer.key_env}"
            )


def test_no_two_cells_on_one_runner_share_a_cache_they_both_save() -> None:
    saved: dict[tuple[str, str | None, str | None, str], int] = defaultdict(int)
    for cache in _rust_caches():
        if cache.saves and cache.shared_key:
            saved[(cache.workflow, cache.shared_key, cache.key, cache.runs_on)] += 1
    # A matrix job whose cells build the same tree (fuzz-smoke) may share one.
    shared_on_purpose = {
        ("ci.yml", "fuzz", "${{ steps.nightly.outputs.version }}", "ubuntu-latest")
    }
    for name, count in saved.items():
        assert count == 1 or name in shared_on_purpose, f"{name} is saved by {count} cells"


def _compiler_cache(job: str, runs_on: str | None = None) -> CompilerCache:
    return next(c for c in _compiler_caches() if c.job == job and runs_on in (None, c.runs_on))


def test_the_engine_debug_tree_is_cached_once() -> None:
    """engine-test's Linux compiler cache serves the Linux jobs that build a
    subset of its debug tree; they never save a copy."""
    _, job, runs_on = ENGINE_DEBUG_PRODUCER
    # The Linux shard that tests opentide-lsp (clients) and opentide-analysis
    # (elastic-sweep): each shard saves the crates its packages build.
    (cell,) = [
        cell
        for cell in _cells(_ci()["jobs"][job])
        if cell["os"] == runs_on
        and {"opentide-lsp", "opentide-analysis"} <= set(ci_matrix.selection(cell["packages"])[0])
    ]
    family = f"sccache-engine-dev-ubuntu-latest-{cell['shard']}-"
    savers = [c for c in _compiler_caches() if c.job == job and (c.saves or "").startswith(family)]
    assert len(savers) == 1, family
    producer = savers[0]
    assert producer.saves is not None
    for _, reader_job in ENGINE_DEBUG_READERS:
        reader = _compiler_cache(reader_job)
        assert reader.restores == producer.saves
        assert reader.saves is None, f"{reader_job} must not save a copy of engine-test's cache"


def test_the_python_jobs_build_the_binding_once() -> None:
    """test's coverage cell (3.14) saves the compiler cache of the binding `uv
    sync` builds; the other Python jobs on Linux restore it."""
    _, producer_job = PYTHON_PRODUCER
    producer = _compiler_cache(producer_job)
    assert producer.saves is not None and producer.saves.startswith("sccache-python-engine-")
    assert "matrix.python-version == env.COVERAGE_PYTHON" in str(producer.save_condition)
    # lint saves a compiler cache of its own (sccache-lint-).
    for _, job in (r for r in PYTHON_READERS if r[1] != "lint"):
        reader = _compiler_cache(job)
        assert reader.restores == producer.saves, job
        assert reader.saves is None, job


def test_a_release_restores_no_cache() -> None:
    """publish.yml restores nothing, and the asset build it shares with the
    dry run keeps no target tree: the dry run's compiler cache (below) is
    restored and saved only under ``inputs.dry-run``."""
    assert not _in("publish.yml"), "the release builds from nothing"
    assert not _in("engine-release-build.yml"), "sccache, not a target tree per target"
    workflow = yaml.safe_load((WORKFLOWS / "engine-release-build.yml").read_text("utf-8"))
    cached = 0
    for job_id, job in workflow["jobs"].items():
        for step in job.get("steps") or []:
            uses = str(step.get("uses", ""))
            run = str(step.get("run", ""))
            sccache = "sccache" in uses + str(step.get("with") or {})
            setup = uses.startswith(("actions/cache", "taiki-e/install-action"))
            if (setup and sccache) or "RUSTC_WRAPPER" in run:
                assert "inputs.dry-run" in str(step.get("if", "")), (job_id, step.get("name"))
                cached += 1
    assert cached >= 8, "the binaries and the WebAssembly builds are cached in the dry run"


def test_a_release_restores_no_other_cache() -> None:
    """Nor any cache of another kind: a setup action's own, or actions/cache
    outside the dry run."""
    for name in ("publish.yml", "engine-release-build.yml"):
        workflow = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
        for job_id, job in workflow["jobs"].items():
            for step in job.get("steps") or []:
                uses = str(step.get("uses", ""))
                inputs = step.get("with") or {}
                if uses.startswith("actions/cache"):
                    assert name == "engine-release-build.yml", (name, job_id)
                    assert "inputs.dry-run" in str(step.get("if", "")), (name, job_id)
                    continue
                assert "cache" not in inputs, (name, job_id, uses)
                if uses.startswith("astral-sh/setup-uv"):
                    # Its default, "auto", caches on GitHub-hosted runners:
                    # it must be turned off by name.
                    assert inputs.get("enable-cache") is False, (name, job_id, uses)
                else:
                    assert "enable-cache" not in inputs, (name, job_id, uses)
                if uses.startswith("actions/setup-node@"):
                    # It may enable npm's cache by itself (a `packageManager` field).
                    assert inputs.get("package-manager-cache") is False, (name, job_id)


# The release dry run's compiler caches (#1047 follow-up): one sccache family
# per Linux runner (arch) for the binaries, one for the WebAssembly builds,
# each saved by one cell from a push when the key missed. Its ten target trees,
# one per target and job, evicted the families pull requests restore.
RELEASE_NATIVE = "sccache-release-${{ runner.os }}-${{ runner.arch }}-"
RELEASE_WASM = "sccache-release-wasm-"


def _release_steps(job_id: str) -> list[dict[str, Any]]:
    workflow = yaml.safe_load((WORKFLOWS / "engine-release-build.yml").read_text("utf-8"))
    return workflow["jobs"][job_id].get("steps") or []


@pytest.mark.parametrize(("job_id", "family"), [("native", RELEASE_NATIVE), ("wasm", RELEASE_WASM)])
def test_the_release_dry_run_keeps_one_compiler_cache_per_runner(job_id: str, family: str) -> None:
    steps = _release_steps(job_id)
    (restore,) = [s for s in steps if str(s.get("uses", "")).startswith(SCCACHE_RESTORE)]
    (save,) = [s for s in steps if str(s.get("uses", "")).startswith(SCCACHE_SAVE)]
    assert restore["with"]["key"] == save["with"]["key"] == family + STABLE_HASH
    assert restore["with"]["restore-keys"] == family + STABLE_HASH.removesuffix(WEEK)
    assert restore["with"]["path"] == save["with"]["path"] == ".sccache"
    condition = str(save["if"])
    assert condition.startswith(DEVELOPMENT_ONLY), condition
    assert "inputs.dry-run" in condition
    assert "steps.sccache.outputs.cache-hit != 'true'" in condition
    # The wrapper is set, and sccache installed, before the first cargo command.
    names = [str(s.get("name", "")) for s in steps]
    builds = ("cargo build", "build-wasm.sh")
    first_cargo = min(
        n for n, s in enumerate(steps) if any(b in str(s.get("run", "")) for b in builds)
    )
    assert names.index("Install sccache") < names.index("Wrap rustc in sccache") < first_cargo


def test_one_release_cell_per_runner_saves_its_compiler_cache() -> None:
    workflow = yaml.safe_load((WORKFLOWS / "engine-release-build.yml").read_text("utf-8"))
    native = workflow["jobs"]["native"]
    (save,) = [s for s in native["steps"] if str(s.get("uses", "")).startswith(SCCACHE_SAVE)]
    assert str(save["if"]).endswith("&& matrix.saves")
    cells = native["strategy"]["matrix"]["include"]
    savers = [c["os"] for c in cells if c["saves"] is True]
    # Every runner has one cell marked to save, and only one (the Intel macOS
    # cross build shares Apple silicon's runner); the save itself runs on
    # Linux only (test_only_linux_keeps_a_compiler_cache).
    assert sorted(savers) == sorted({c["os"] for c in cells})
    assert LINUX_ONLY in str(save["if"])
    assert [c["target"] for c in cells if c["saves"] is False] == ["x86_64-apple-darwin"]


def test_the_benchmarks_restore_the_full_sets_cache_and_save_none() -> None:
    """bench.yml's nightly runs saved two target trees; it now restores the
    full set's Linux compiler cache, with the environment of the job that
    saves it (`conformance`), so that the crates both build hit."""
    workflow = yaml.safe_load((WORKFLOWS / "bench.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["bench"]
    uses = [str(s.get("uses", "")) for s in job["steps"]]
    assert not any(u.startswith((RUST_CACHE, SCCACHE_SAVE, "actions/cache@")) for u in uses)
    (restore,) = [s for s in job["steps"] if str(s.get("uses", "")).startswith(SCCACHE_RESTORE)]
    assert restore["with"]["key"] == FULL_SET_FAMILY + STABLE_HASH
    assert restore["with"]["restore-keys"] == FULL_SET_FAMILY + STABLE_HASH.removesuffix(WEEK)
    conformance = _ci()["jobs"]["conformance"]["env"]
    for name in ("RUSTFLAGS", "CARGO_PROFILE_DEV_DEBUG", "RUSTC_WRAPPER", "SCCACHE_DIR"):
        assert job["env"][name] == conformance[name], name
    assert str(job["runs-on"]).startswith("ubuntu"), "the Linux family"


# sccache (#841): the workspace's own crates, which rust-cache drops before
# saving, cached by content. Each cache name has one job that saves it.
SCCACHE_RESTORE = "actions/cache/restore@"
SCCACHE_SAVE = "actions/cache/save@"
SCCACHE_KEY = re.compile(
    r"^sccache-(?P<name>.+)-\$\{\{ hashFiles\(.*\) \}\}-\$\{\{ steps\.week\.outputs\.week \}\}$"
)


class CompilerCache(NamedTuple):
    job: str
    runs_on: str
    restores: str | None
    saves: str | None
    save_condition: str | None


def _ci() -> dict[str, Any]:
    return yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))


def _compiler_caches() -> list[CompilerCache]:
    caches: list[CompilerCache] = []
    for job_id, job in _ci()["jobs"].items():
        steps = job.get("steps") or []
        restores = [s for s in steps if str(s.get("uses", "")).startswith(SCCACHE_RESTORE)]
        saves = [s for s in steps if str(s.get("uses", "")).startswith(SCCACHE_SAVE)]
        assert len(restores) <= 1 and len(saves) <= 1, job_id
        for cell in _cells(job):
            restore = _resolve((restores[0]["with"] if restores else {}).get("key"), cell)
            save = _resolve((saves[0]["with"] if saves else {}).get("key"), cell)
            caches.append(
                CompilerCache(
                    job=job_id,
                    runs_on=str(_resolve(job.get("runs-on"), cell)),
                    restores=restore,
                    saves=save,
                    save_condition=saves[0].get("if") if saves else None,
                )
            )
    return caches


def _wraps_with_sccache(job: dict[str, Any]) -> bool:
    return (job.get("env") or {}).get("RUSTC_WRAPPER") == "sccache"


def test_a_job_that_wraps_rustc_in_sccache_installs_it_first() -> None:
    """RUSTC_WRAPPER=sccache without the binary fails every cargo command."""
    jobs = _ci()["jobs"]
    wrapped = [job_id for job_id, job in jobs.items() if _wraps_with_sccache(job)]
    expected = {"engine-test-part", "test", "cli-e2e", "golden-compare-part", "corpus-part", "wasi"}
    assert expected <= set(wrapped)
    for job_id in wrapped:
        steps = jobs[job_id]["steps"]
        installs = [
            n
            for n, s in enumerate(steps)
            if (s.get("with") or {}).get("tool", "").startswith("sccache@")
        ]
        assert len(installs) == 1, job_id
        cargo = [
            n
            for n, s in enumerate(steps)
            if re.search(r"\b(cargo|uv sync|uv build|uv run)\b", str(s.get("run", "")))
        ]
        # npm-install builds through node only: no cargo line, but the wrapper still applies.
        assert not cargo or installs[0] < min(cargo), f"{job_id}: install sccache before cargo"
        restores = [s for s in steps if str(s.get("uses", "")).startswith(SCCACHE_RESTORE)]
        assert len(restores) == 1, f"{job_id}: restore a compiler cache"
        directory = str((jobs[job_id].get("env") or {}).get("SCCACHE_DIR", ""))
        # actions/cache refuses a path with `..` (a warning, and nothing saved).
        assert directory and ".." not in directory.split("/"), (job_id, directory)
        assert directory == "${{ github.workspace }}/.sccache", (job_id, directory)
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".sccache/" in ignored, "engine-test fails when the tests leave a file git shows"


def test_every_compiler_cache_has_one_saver_and_its_readers_restore_its_name() -> None:
    caches = _compiler_caches()
    for cache in caches:
        for key in (cache.restores, cache.saves):
            if key is not None:
                assert SCCACHE_KEY.match(key), (cache.job, key)
        if cache.saves is not None:
            assert cache.saves == cache.restores, f"{cache.job}: save the key it restores"
            # An exact hit has nothing new to save.
            assert "steps.sccache.outputs.cache-hit != 'true'" in str(cache.save_condition)
    # One job per name (test's cells save under a matrix condition: its 3.14 cell).
    savers: dict[str, set[str]] = defaultdict(set)
    for cache in caches:
        if cache.saves is not None:
            savers[cache.saves].add(cache.job)
    for key, producers in savers.items():
        assert len(producers) == 1, f"{key} is saved by {sorted(producers)}"
    saved = set(savers)
    for cache in caches:
        if cache.restores is not None:
            assert cache.restores in saved, (
                f"{cache.job} restores {cache.restores}: no job saves it"
            )


def test_the_python_jobs_share_one_pyo3_configuration() -> None:
    """PyO3's build script reruns when PYO3_PYTHON changes, and cargo rebuilds
    every engine crate above it: each Python job names the same interpreter, so
    the binding in the cache is the one it builds (#841)."""
    jobs = _ci()["jobs"]
    python_jobs = [job for workflow, job in (PYTHON_PRODUCER, *PYTHON_READERS)]
    python_jobs += ["cli-e2e-full", "golden-compare-part"]
    seen = {(jobs[job].get("env") or {}).get("PYO3_PYTHON") for job in python_jobs}
    assert seen == {"/usr/bin/python3"}, seen


def _pull_request_workflows() -> list[Path]:
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        triggers = workflow.get("on", workflow.get(True)) or {}
        if "pull_request" in triggers or "workflow_call" in triggers:
            found.append(path)
    return found


def test_no_cache_is_saved_from_a_pull_request() -> None:
    """Every rust-cache and sccache save in a workflow a pull request runs
    (or calls) saves on a push only: pull requests restore."""
    checked = 0
    for path in _pull_request_workflows():
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (workflow.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                uses = str(step.get("uses", ""))
                where = f"{path.name} {job_id}"
                if uses.startswith(RUST_CACHE):
                    save_if = (step.get("with") or {}).get("save-if", True)
                    if save_if is False:
                        continue
                    save_if = str(save_if)
                    allowed = (
                        "${{ " + PUSH_ONLY,
                        "${{ github.event_name != 'pull_request'",
                        TARGET_TREE_SAVE,
                    )
                    assert save_if.startswith(allowed), (
                        f"{where}: rust-cache saves on a pull request ({save_if})"
                    )
                    checked += 1
                elif uses.startswith(SCCACHE_SAVE):
                    condition = str(step.get("if", ""))
                    assert condition.startswith((PUSH_ONLY, DEVELOPMENT_ONLY)), where
                    checked += 1
                elif uses.startswith("actions/cache@"):
                    raise AssertionError(f"{where}: actions/cache saves on every event")
    # The jobs that saved rust-cache trees now save one stable compiler cache
    # per family (#1047): fewer saves, each checked.
    assert checked >= 15


# The compiler cache's key: one per family (and OS), stable for a week of one
# toolchain. A key that hashed the sources made every push to a base branch
# save a new copy of each family (about 4 GB a push, #1047); one that hashed
# Cargo.lock still did on most merges, which change it, and the families pull
# requests restore were evicted from the 10 GB a repository keeps before the
# next pull request read them (#841). sccache is content-addressed, so a copy
# a few days old still serves every crate that did not change.
STABLE_HASH = "${{ hashFiles('rust-toolchain.toml') }}-${{ steps.week.outputs.week }}"
WEEK = "${{ steps.week.outputs.week }}"
WEEK_RUN = 'echo "week=$(date -u +%G-W%V)" >> "$GITHUB_OUTPUT"'
# Target trees (rust-cache) are saved by the nightly and on pushes to
# development only, whose caches every pull request reads.
TARGET_TREE_SAVE = (
    "${{ github.event_name == 'schedule' || github.ref == 'refs/heads/development' }}"
)
# The full set's jobs that built a rust-cache tree of their own now share one
# compiler cache per OS, which `conformance` saves on each.
FULL_SET_FAMILY = "sccache-full-set-${{ runner.os }}-"
FULL_SET_JOBS = {
    "facade",
    "node",
    "npm-install",
    "conformance",
    "engine-wasm",
    "engine-package",
    "bench",
}
# macOS and Windows keep no compiler cache (#841): their families (a gigabyte
# each, saved by every push's full set on each base branch) crowded the Linux
# families every pull request restores out of the 10 GB a repository keeps.
# They run in the full set only, which no pull request's gates wait on.
LINUX_ONLY = "runner.os == 'Linux'"


def _sccache_steps() -> list[tuple[str, dict[str, Any]]]:
    return [
        (job_id, step)
        for job_id, job in _ci()["jobs"].items()
        for step in job.get("steps") or []
        if str(step.get("uses", "")).startswith((SCCACHE_RESTORE, SCCACHE_SAVE))
    ]


def test_a_compiler_cache_key_changes_only_with_the_toolchain_and_the_week() -> None:
    steps = _sccache_steps()
    assert len(steps) >= 15
    for job_id, step in steps:
        key = str(step["with"]["key"])
        assert key.endswith("-" + STABLE_HASH), (job_id, key)
        assert "Cargo.lock" not in key, (job_id, key)
        if str(step["uses"]).startswith(SCCACHE_RESTORE):
            # A new week restores the newest copy of its family and toolchain.
            assert step["with"].get("restore-keys") == key.removesuffix(WEEK), job_id


@pytest.mark.parametrize("name", ["ci.yml", "bench.yml", "engine-release-build.yml"])
def test_the_week_is_computed_before_each_compiler_cache_restore(name: str) -> None:
    """`steps.week.outputs.week` is the ISO week (UTC) of the run, set by the
    step just before the restore, under the restore's own condition."""
    workflow = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    found = 0
    for job_id, job in workflow["jobs"].items():
        steps = job.get("steps") or []
        for at, step in enumerate(steps):
            if not str(step.get("uses", "")).startswith(SCCACHE_RESTORE):
                continue
            week = steps[at - 1]
            assert week.get("id") == "week", (name, job_id)
            assert week["run"] == WEEK_RUN and week["shell"] == "bash", (name, job_id)
            assert week.get("if") == step.get("if"), (name, job_id)
            found += 1
    assert found, name


def test_the_week_is_iso_8601() -> None:
    """`date -u +%G-W%V`: the ISO year and week, so that the last days of
    December and the first of January share a key when they share a week."""
    import subprocess

    week = subprocess.run(
        ["bash", "-c", "date -u -d 2026-12-31 +%G-W%V; date -u -d 2027-01-01 +%G-W%V"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert week == ["2026-W53", "2026-W53"]


def test_target_trees_are_saved_by_the_nightly_and_development_only() -> None:
    """Every rust-cache that saves on a base branch's event saves on the
    nightly and pushes to development only; a pull request's ref
    (`refs/pull/N/merge`) never saves."""
    checked = 0
    for path in _pull_request_workflows():
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (workflow.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                if not str(step.get("uses", "")).startswith(RUST_CACHE):
                    continue
                save_if = (step.get("with") or {}).get("save-if", True)
                if save_if is False:
                    continue
                assert save_if == TARGET_TREE_SAVE, (path.name, job_id, save_if)
                checked += 1
    assert checked >= 6


def test_a_job_with_a_compiler_cache_restores_no_target_tree() -> None:
    """rust-cache's target tree (about 0.7 GB a job family) is what sccache
    already covers; keeping both doubled what a push saved."""
    for job_id, job in _ci()["jobs"].items():
        uses = [str(step.get("uses", "")) for step in job.get("steps") or []]
        if any(u.startswith(SCCACHE_RESTORE) for u in uses):
            assert not any(u.startswith(RUST_CACHE) for u in uses), job_id


def test_the_full_set_shares_one_compiler_cache_per_os() -> None:
    jobs = _ci()["jobs"]
    for job_id in FULL_SET_JOBS:
        assert _wraps_with_sccache(jobs[job_id]), job_id
        cache = _compiler_cache(job_id)
        assert cache.restores == FULL_SET_FAMILY + STABLE_HASH, job_id
    savers = {c.job for c in _compiler_caches() if c.saves == FULL_SET_FAMILY + STABLE_HASH}
    assert savers == {"conformance"}
    # Saved on development and by the nightly only: a pull request's full set
    # restores development's (#841). Linux's only: conformance's macOS and
    # Windows cells build without one.
    (saver,) = {c.save_condition for c in _compiler_caches() if c.job == "conformance"}
    assert str(saver).startswith(DEVELOPMENT_ONLY), saver
    assert str(saver).endswith(LINUX_ONLY), saver
    used = {str(jobs[j]["runs-on"]) for j in FULL_SET_JOBS if j != "conformance"}
    assert used == {"ubuntu-latest"}, used


def _runs_on_linux(job: dict[str, Any]) -> bool:
    """Every cell of the job runs on Linux."""
    return all(str(_resolve(job.get("runs-on"), cell)).startswith("ubuntu") for cell in _cells(job))


@pytest.mark.parametrize("name", ["ci.yml", "engine-release-build.yml"])
def test_only_linux_keeps_a_compiler_cache(name: str) -> None:
    """A compiler cache is restored and saved on Linux only: in a job that
    runs on Linux alone, or under `runner.os == 'Linux'` (with its week)."""
    workflow = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    checked = 0
    for job_id, job in workflow["jobs"].items():
        steps = job.get("steps") or []
        cached = [
            s
            for s in steps
            if str(s.get("uses", "")).startswith((SCCACHE_RESTORE, SCCACHE_SAVE))
            or s.get("id") == "week"
        ]
        if not cached or _runs_on_linux(job):
            continue
        for step in cached:
            assert LINUX_ONLY in str(step.get("if", "")), (name, job_id, step.get("name"))
            checked += 1
    assert checked
    # cli-windows-smoke, on Windows alone, has no compiler cache at all.
    smoke = _ci()["jobs"]["cli-windows-smoke"]
    assert not _wraps_with_sccache(smoke)
    assert not any(
        str(s.get("uses", "")).startswith((SCCACHE_RESTORE, SCCACHE_SAVE)) for s in smoke["steps"]
    )


def test_the_wasi_job_keeps_a_core_family_of_its_own() -> None:
    """The WASI command line's job is in the core set and builds what no other
    job does (the module for wasm32-wasip1 in the `wasi` profile, and xtask):
    it restored the full set's family, which it never saved, and compiled most
    of it again on every run (#841)."""
    cache = _compiler_cache("wasi")
    family = "sccache-wasi-" + STABLE_HASH
    assert cache.restores == cache.saves == family
    assert str(cache.save_condition).startswith(PUSH_ONLY), cache.save_condition
    assert {c.job for c in _compiler_caches() if c.restores == family} == {"wasi"}
    names = [str(s.get("name", "")) for s in _ci()["jobs"]["wasi"]["steps"]]
    # xtask builds in a step of its own, before the compare that runs it.
    assert names.index("Build xtask") < names.index(
        "Every golden case that needs no network, through the WASI module"
    )


def test_only_the_fuzz_jobs_keep_a_target_tree_in_ci() -> None:
    """fuzz-smoke builds with the nightly in fuzz/target and caches its
    cargo-fuzz binary in ~/.cargo/bin: the one rust-cache left in ci.yml."""
    assert {c.job for c in _in("ci.yml")} == {"fuzz-smoke"}


# The core families (every pull request's jobs) are saved per base branch, from
# a push to it: a pull request reads its base branch's caches. The full set's
# and the release dry run's are saved on development and by the nightly only,
# whose caches every branch reads: a copy of those per base branch (with
# integration and a release train both active) did not fit beside the core
# families in the 10 GB a repository keeps, and evicted them (#841).
def test_only_the_core_families_are_saved_per_base_branch() -> None:
    full_set_and_release = 0
    for cache in _compiler_caches():
        if cache.saves is None:
            continue
        condition = str(cache.save_condition)
        if cache.saves.startswith(("sccache-full-set-", "sccache-release-")):
            assert condition.startswith(DEVELOPMENT_ONLY), (cache.job, condition)
            full_set_and_release += 1
        else:
            assert condition.startswith(PUSH_ONLY), (cache.job, condition)
    assert full_set_and_release
    for job_id in ("native", "wasm"):
        (save,) = [
            s for s in _release_steps(job_id) if str(s.get("uses", "")).startswith(SCCACHE_SAVE)
        ]
        assert str(save["if"]).startswith(DEVELOPMENT_ONLY), (job_id, save["if"])
