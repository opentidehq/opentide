"""The Rust caches of the repository's workflows.

GitHub keeps 10 GB of Actions caches per repository and evicts the oldest
beyond that. engine-ci.yml's ``clients`` and ``elastic-sweep`` jobs build a
subset of ci.yml's ``engine`` debug tree, so they read its cache (one
``shared-key``, ``save-if: false``) instead of each saving a copy of their own,
as they did in language-server's CI.

Swatinem/rust-cache hashes the job's ``CARGO*``, ``CC*``, ``CFLAGS*``,
``CXX*``, ``CMAKE*`` and ``RUST*`` environment variables into the key (the
"Environment considered" list in its log), so a reader whose environment
differs from the producer's computes another key and never restores anything.
"""

from __future__ import annotations

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

ENGINE_DEBUG_PRODUCER = ("ci.yml", "engine")
ENGINE_DEBUG_READERS = (("engine-ci.yml", "clients"), ("engine-ci.yml", "elastic-sweep"))


class RustCache(NamedTuple):
    workflow: str
    job: str
    runs_on: str
    shared_key: str | None
    saves: bool
    workspaces: str
    key_env: dict[str, str]


def _env(block: dict[str, Any]) -> dict[str, str]:
    return {str(name): str(value) for name, value in (block.get("env") or {}).items()}


def _rust_caches() -> dict[tuple[str, str], RustCache]:
    caches: dict[tuple[str, str], RustCache] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (workflow.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                if not str(step.get("uses", "")).startswith(RUST_CACHE):
                    continue
                inputs = step.get("with") or {}
                env = {**_env(workflow), **_env(job), **_env(step)}
                assert (path.name, job_id) not in caches, f"{path.name} {job_id}: two Rust caches"
                caches[(path.name, job_id)] = RustCache(
                    workflow=path.name,
                    job=job_id,
                    runs_on=str(job.get("runs-on")),
                    shared_key=inputs.get("shared-key"),
                    # `save-if` defaults to true; an expression saves on some events.
                    saves=inputs.get("save-if", True) is not False,
                    workspaces=str(inputs.get("workspaces", DEFAULT_WORKSPACES)),
                    key_env={k: v for k, v in env.items() if k.startswith(KEY_ENV_PREFIXES)},
                )
    return caches


def test_the_engine_debug_tree_is_cached_once() -> None:
    caches = _rust_caches()
    producer = caches[ENGINE_DEBUG_PRODUCER]
    assert producer.shared_key, "ci.yml's engine job saves the shared engine debug cache"
    assert producer.saves
    for reader in ENGINE_DEBUG_READERS:
        cache = caches[reader]
        assert cache.shared_key == producer.shared_key, f"{reader} reads the engine job's cache"
        assert not cache.saves, f"{reader} must not save a copy of the engine job's cache"


def test_every_shared_rust_cache_has_one_producer_with_the_readers_key() -> None:
    groups: dict[str, list[RustCache]] = defaultdict(list)
    for cache in _rust_caches().values():
        if cache.shared_key:
            groups[cache.shared_key].append(cache)
    assert groups
    for key, caches in groups.items():
        producers = [cache for cache in caches if cache.saves]
        assert len(producers) == 1, f"shared-key {key}: one job saves it, not {producers}"
        producer = producers[0]
        for cache in caches:
            where = f"shared-key {key}: {cache.workflow} {cache.job}"
            assert cache.runs_on == producer.runs_on, where
            assert cache.workspaces == producer.workspaces, where
            # Otherwise rust-cache computes another key and the reader restores nothing.
            assert cache.key_env == producer.key_env, (
                f"{where} has {cache.key_env}, its producer "
                f"{producer.workflow} {producer.job} {producer.key_env}"
            )
