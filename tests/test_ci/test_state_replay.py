"""The production write-back's state-only fallback replays per tenant (RFC 0010, #548).

When the rule write-back conflicts with a concurrent merge, the deployment
state is pushed alone. These cases pin what that commit must contain: this
run's bindings, every binding another run recorded, and the deletions both
runs made, never a copy of this run's whole state folder.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_ci.test_production_writeback import (  # noqa: F401 - fixtures
    _bash,
    _git,
    fake_cli,
    git_identity,
)

from opentide.ci.state_replay import replay
from opentide.ci.writeback import (
    SIDE_REF_PREFIX,
    STATE_BASE_MESSAGE,
    WRITEBACK_MESSAGE,
    WRITEBACK_REPLAY_FAILED,
    WRITEBACK_STATE_ONLY,
    overlay_default_branch_state,
    production_writeback,
)

STATES = ".opentide/states/deployment"
S = "00000000-0000-4000-8003-0000000000a1"
X = "00000000-0000-4000-8003-0000000000a2"
Y = "00000000-0000-4000-8003-0000000000a3"
N = "00000000-0000-4000-8003-0000000000a4"


def _shard(uuid: str, tenants: dict[str, str]) -> str:
    payload = {
        "object_uuid": uuid,
        "platforms": {"defender_for_endpoint": tenants},
        "schema": "deployment.state::1.0",
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _write(repo: Path, uuid: str, tenants: dict[str, str] | None) -> None:
    path = repo / STATES / f"{uuid}.json"
    if tenants is None:
        path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_shard(uuid, tenants), encoding="utf-8")


def _tenants(repo: Path, ref: str, uuid: str) -> dict[str, str] | None:
    done = _git(repo, "ls-tree", "--name-only", ref, f"{STATES}/")
    if f"{STATES}/{uuid}.json" not in done.splitlines():
        return None
    text = _git(repo, "show", f"{ref}:{STATES}/{uuid}.json")
    return json.loads(text)["platforms"]["defender_for_endpoint"]


@pytest.fixture
def remote(tmp_path: Path, git_identity: None, fake_cli: Path) -> Path:  # noqa: F811
    """A default branch with three shards and one rule."""
    del git_identity, fake_cli
    bare = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    _git(tmp_path, "clone", "-q", str(bare), str(seed))
    (seed / "objects" / "rules").mkdir(parents=True)
    (seed / "objects" / "rules" / "rule.yaml").write_text("status: STAGING\n", encoding="utf-8")
    _write(seed, S, {"contoso": "1"})
    _write(seed, X, {"contoso": "5"})
    _write(seed, Y, {"contoso": "6"})
    _git(seed, "add", "-A")
    _git(seed, "commit", "-q", "-m", "catalogue")
    _git(seed, "push", "-q", "origin", "HEAD:main")
    return bare


def _clone(remote: Path, name: str) -> Path:
    work = remote.parent / name
    _git(remote.parent, "clone", "-q", str(remote), str(work))
    return work


def _concurrent(remote: Path, change) -> None:
    """Another production run lands after this run checked out: the push will be rejected."""
    other = _clone(remote, "other")
    (other / "objects" / "rules" / "rule.yaml").write_text("status: DISABLED\n", encoding="utf-8")
    change(other)
    _git(other, "add", "-A")
    _git(other, "commit", "-q", "-m", "concurrent production run")
    _git(other, "push", "-q", "origin", "HEAD:main")


def _writeback(work: Path):
    script = production_writeback(
        rules="objects/rules",
        push='git push -q origin "HEAD:main"',
        fetch="git fetch -q origin main",
    )
    return _bash(script, work)


def _tip(work: Path) -> str:
    _git(work, "fetch", "-q", "origin", "main")
    return "FETCH_HEAD"


def test_state_only_push_merges_with_a_concurrent_run(remote: Path) -> None:
    """The reviewer's case: no revert, no resurrection, both runs' bindings kept."""

    def theirs(repo: Path) -> None:
        _write(repo, S, {"contoso": "1", "fabrikam": "2"})
        _write(repo, Y, None)

    work = _clone(remote, "work")
    _concurrent(remote, theirs)
    (work / "objects" / "rules" / "rule.yaml").write_text("status: PRODUCTION\n", encoding="utf-8")
    _write(work, S, {"contoso": "1", "tailspin": "3"})
    _write(work, X, None)
    _write(work, N, {"contoso": "7"})

    result = _writeback(work)

    assert result.returncode == 1, result.stderr
    assert WRITEBACK_STATE_ONLY in result.stderr
    tip = _tip(work)
    assert _tenants(work, tip, N) == {"contoso": "7"}
    assert _tenants(work, tip, S) == {"contoso": "1", "fabrikam": "2", "tailspin": "3"}
    assert _tenants(work, tip, X) is None
    assert _tenants(work, tip, Y) is None
    assert _git(work, "show", f"{tip}:objects/rules/rule.yaml") == "status: DISABLED"


def test_a_deletion_only_run_still_lands(remote: Path) -> None:
    work = _clone(remote, "work")
    _concurrent(remote, lambda repo: None)
    (work / "objects" / "rules" / "rule.yaml").write_text("status: PRODUCTION\n", encoding="utf-8")
    _write(work, X, None)

    result = _writeback(work)

    assert result.returncode == 1, result.stderr
    tip = _tip(work)
    assert _tenants(work, tip, X) is None
    assert _tenants(work, tip, S) == {"contoso": "1"}
    assert _tenants(work, tip, Y) == {"contoso": "6"}


def test_same_binding_changed_by_both_runs_keeps_ours_and_reports(remote: Path) -> None:
    work = _clone(remote, "work")
    _concurrent(remote, lambda repo: _write(repo, S, {"contoso": "9"}))
    (work / "objects" / "rules" / "rule.yaml").write_text("status: PRODUCTION\n", encoding="utf-8")
    _write(work, S, {"contoso": "8"})

    result = _writeback(work)

    assert result.returncode == 1, result.stderr
    assert "deployment_state_conflict" in result.stderr
    assert "'8'" in result.stderr and "'9'" in result.stderr
    assert _tenants(work, _tip(work), S) == {"contoso": "8"}


def test_replay_applies_only_the_commit_delta(remote: Path) -> None:
    """Unit level: the working tree is the tip; the delta comes from one commit."""
    work = _clone(remote, "work")
    _write(work, S, {"contoso": "1", "tailspin": "3"})
    _write(work, X, None)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "ours")
    ours = _git(work, "rev-parse", "HEAD")
    _git(work, "reset", "-q", "--hard", "HEAD^")
    _write(work, Y, {"contoso": "6", "fabrikam": "4"})

    result = replay(work, ours)

    assert result.conflicts == []
    assert json.loads((work / STATES / f"{S}.json").read_text())["platforms"] == {
        "defender_for_endpoint": {"contoso": "1", "tailspin": "3"}
    }
    assert not (work / STATES / f"{X}.json").exists()
    assert json.loads((work / STATES / f"{Y}.json").read_text())["platforms"] == {
        "defender_for_endpoint": {"contoso": "6", "fabrikam": "4"}
    }


def test_a_failed_replay_keeps_the_ids_on_a_side_ref(remote: Path) -> None:
    """A malformed tip shard stops the replay; the recorded ids must stay recoverable."""

    def theirs(repo: Path) -> None:
        (repo / STATES / f"{S}.json").write_text("not json\n", encoding="utf-8")

    work = _clone(remote, "work")
    _concurrent(remote, theirs)
    (work / "objects" / "rules" / "rule.yaml").write_text("status: PRODUCTION\n", encoding="utf-8")
    _write(work, S, {"contoso": "1", "tailspin": "3"})
    _write(work, N, {"contoso": "7"})

    result = _writeback(work)

    assert result.returncode == 1, result.stderr
    assert WRITEBACK_REPLAY_FAILED in result.stderr
    assert '"tailspin": "3"' in result.stderr and '"contoso": "7"' in result.stderr
    refs = _git(work, "ls-remote", "origin", f"{SIDE_REF_PREFIX}*").splitlines()
    assert len(refs) == 1
    side = refs[0].split()[0]
    _git(work, "fetch", "-q", "origin", refs[0].split()[1])
    assert _tenants(work, side, N) == {"contoso": "7"}
    # Nothing broken reached the default branch.
    assert _tenants(work, _tip(work), N) is None


def test_replay_state_cli_runs_the_replay(remote: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The write-back calls ``opentide deploy replay-state``.

    A subcommand, so the replay runs in opentide's own interpreter.
    """
    from typer.testing import CliRunner

    from opentide.cli import app

    work = _clone(remote, "work")
    _write(work, X, None)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "ours")
    ours = _git(work, "rev-parse", "HEAD")
    _git(work, "reset", "-q", "--hard", "HEAD^")
    monkeypatch.chdir(work)

    result = CliRunner().invoke(app, ["deploy", "replay-state", ours])

    assert result.exit_code == 0, result.stdout
    assert "1 removed" in result.stdout
    assert not (work / STATES / f"{X}.json").exists()


# --- The deploy reads the default branch's state, not the triggering commit's --


def _overlay(work: Path):
    return _bash(overlay_default_branch_state(fetch="git fetch -q origin main"), work)


def test_back_to_back_merges_update_the_rule_the_earlier_run_created(remote: Path) -> None:
    """Review issue 2: run A recorded N after this run's commit was made.

    Without the overlay the checkout has no shard for N, and the deploy creates
    N a second time. With it, the deploy sees A's id and updates. The write-back
    then pushes only this run's change: no state-only fallback, no revert of
    A's deletion of Y, and no overlay commit on the default branch.
    """
    work = _clone(remote, "work")
    triggering = _git(work, "rev-parse", "HEAD")

    def run_a(repo: Path) -> None:
        _write(repo, N, {"contoso": "7"})
        _write(repo, Y, None)

    _concurrent(remote, run_a)

    overlay = _overlay(work)

    assert overlay.returncode == 0, overlay.stderr
    assert _git(work, "rev-parse", "HEAD") == triggering
    assert json.loads((work / STATES / f"{N}.json").read_text())["platforms"] == {
        "defender_for_endpoint": {"contoso": "7"}
    }
    assert not (work / STATES / f"{Y}.json").exists()

    # The deploy updates N on contoso and creates it on a second tenant.
    _write(work, N, {"contoso": "7", "fabrikam": "8"})

    result = _writeback(work)

    assert result.returncode == 0, result.stderr
    assert WRITEBACK_STATE_ONLY not in result.stderr
    tip = _tip(work)
    assert _tenants(work, tip, N) == {"contoso": "7", "fabrikam": "8"}
    assert _tenants(work, tip, Y) is None
    assert _tenants(work, tip, S) == {"contoso": "1"}
    assert _git(work, "show", f"{tip}:objects/rules/rule.yaml") == "status: DISABLED"
    log = _git(work, "log", "--format=%s", tip).splitlines()
    assert log == [WRITEBACK_MESSAGE, "concurrent production run", "catalogue"]
    assert STATE_BASE_MESSAGE not in log
    changed = _git(work, "show", "--name-only", "--format=", tip).splitlines()
    assert changed == [f"{STATES}/{N}.json"]


def test_a_default_branch_without_state_removes_the_checkout_copy(remote: Path) -> None:
    work = _clone(remote, "work")
    _concurrent(remote, lambda repo: _git(repo, "rm", "-q", "-r", STATES))

    assert _overlay(work).returncode == 0
    assert not (work / STATES).exists()
    result = _writeback(work)
    assert result.returncode == 0, result.stderr
    assert "No deployment write-backs to commit" in result.stdout


def test_an_unchanged_state_adds_no_overlay_commit(remote: Path) -> None:
    work = _clone(remote, "work")
    head = _git(work, "rev-parse", "HEAD")

    assert _overlay(work).returncode == 0

    base = (work / _git(work, "rev-parse", "--git-path", "opentide-state-base")).read_text()
    assert base.strip() == head
    _write(work, N, {"contoso": "7"})
    result = _writeback(work)
    assert result.returncode == 0, result.stderr
    tip = _tip(work)
    assert _git(work, "rev-parse", f"{tip}^") == head
