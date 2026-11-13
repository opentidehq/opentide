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

A release builds from nothing: engine-release.yml restores no cache, and the
asset build it shares with ci.yml's dry run (engine-release-build.yml) restores
one only under ``inputs.dry-run``.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any, NamedTuple

import yaml

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
    """The job's matrix cells (one empty cell without a matrix): the product of
    its axes, or its `include` entries when it has no axes."""
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    if isinstance(matrix, str):
        return [{}]
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    cells: list[dict[str, str]] = [{}]
    for name, values in axes.items():
        cells = [{**cell, name: str(value)} for cell in cells for value in values]
    if not axes and matrix.get("include"):
        cells = [{str(k): str(v) for k, v in entry.items()} for entry in matrix["include"]]
    return cells


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


def test_the_engine_debug_tree_is_cached_once() -> None:
    caches = _rust_caches()
    producer = next(c for c in caches if (c.workflow, c.job, c.runs_on) == ENGINE_DEBUG_PRODUCER)
    assert producer.shared_key == "engine-dev"
    assert producer.saves
    for workflow, job in ENGINE_DEBUG_READERS:
        reader = next(c for c in caches if (c.workflow, c.job) == (workflow, job))
        assert _name(reader) == _name(producer), f"{job} reads engine-test's Linux cache"
        assert not reader.saves, f"{job} must not save a copy of engine-test's cache"


def test_the_python_jobs_build_the_binding_once() -> None:
    caches = _rust_caches()
    cells = [c for c in caches if (c.workflow, c.job) == PYTHON_PRODUCER]
    assert {c.shared_key for c in cells} == {"python-engine"}
    # The coverage cell (3.14) saves; 3.10 reads, as test-full's cells do.
    assert [c.saves for c in cells].count(True) == 1
    for workflow, job in PYTHON_READERS:
        for reader in (c for c in caches if (c.workflow, c.job) == (workflow, job)):
            assert reader.shared_key == "python-engine", job
            assert not reader.saves, job


def test_a_release_restores_no_cache() -> None:
    assert not _in("engine-release.yml"), "the release builds from nothing"
    build = _in("engine-release-build.yml")
    assert build, "the dry run of the asset build is cached"
    for cache in build:
        assert cache.condition == "inputs.dry-run", (cache.job, cache.condition)


def test_a_release_restores_no_other_cache() -> None:
    """Nor any cache of another kind: actions/cache, or a setup action's own."""
    for name in ("engine-release.yml", "engine-release-build.yml"):
        workflow = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
        for job_id, job in workflow["jobs"].items():
            for step in job.get("steps") or []:
                uses = str(step.get("uses", ""))
                inputs = step.get("with") or {}
                assert not uses.startswith("actions/cache"), (name, job_id)
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


# sccache (#841): the workspace's own crates, which rust-cache drops before
# saving, cached by content. Each cache name has one job that saves it.
SCCACHE_RESTORE = "actions/cache/restore@"
SCCACHE_SAVE = "actions/cache/save@"
SCCACHE_KEY = re.compile(r"^sccache-(?P<name>.+)-\$\{\{ hashFiles\(.*\) \}\}$")


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
    assert {"engine-test-part", "test", "cli-e2e", "golden-compare", "corpus-part"} <= set(wrapped)
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
        assert cargo and installs[0] < min(cargo), f"{job_id}: install sccache before cargo"
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
    python_jobs += ["cli-e2e-full", "golden-compare"]
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
                    assert save_if.startswith("${{ " + PUSH_ONLY) or save_if.startswith(
                        "${{ github.event_name != 'pull_request'"
                    ), f"{where}: rust-cache saves on a pull request ({save_if})"
                    checked += 1
                elif uses.startswith(SCCACHE_SAVE):
                    assert str(step.get("if", "")).startswith(PUSH_ONLY), where
                    checked += 1
                elif uses.startswith("actions/cache@"):
                    raise AssertionError(f"{where}: actions/cache saves on every event")
    assert checked >= 20
