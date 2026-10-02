"""The inflight commit fragment must be runnable before any shard exists."""

from __future__ import annotations

from opentide.ci.inflight import _commit_and_push


def test_commit_and_push_creates_inflight_before_git_add() -> None:
    script = _commit_and_push(
        message="ci: prune inflight preview shards [skip ci]",
        empty_note="No inflight prune changes",
        push="git push origin HEAD:main",
        fetch="git fetch origin main",
    )
    mkdir = script.index("mkdir -p .opentide/inflight")
    add = script.index("git add .opentide/inflight/")
    assert mkdir < add
