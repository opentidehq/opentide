"""Replay one commit's deployment-state changes onto the current checkout (RFC 0010).

The production write-back falls back to pushing the deployment state alone when
its rule files conflict with a concurrent merge (#548). Copying this run's
``.opentide/states/deployment/`` over the tip would revert shards other runs
updated and resurrect shards that were deleted, so this module applies only
what *state_commit* changed relative to its parent, per platform and tenant:

- a binding this run added or changed is set on the tip's shard;
- a binding this run removed is removed from it, and a shard left with no
  binding is deleted;
- every binding this run did not touch keeps the tip's value.

When a concurrent run changed the same binding to a different id, this run's
id is kept (it is the newest record of what this run created) and both ids are
printed as ``deployment_state_conflict`` so the duplicate can be cleaned up.

Usage, from the repository root after resetting to the new tip::

    opentide deploy replay-state <state_commit>
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from opentide.states.deployment import DeploymentState

DEPLOYMENT_STATES = ".opentide/states/deployment"


@dataclass
class ReplayResult:
    """What the replay changed, for the CI log and for tests."""

    written: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)


def _git(root: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True, encoding="utf-8"
    )
    return done.stdout


def _blob(root: Path, revision: str, path: str) -> str | None:
    done = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return done.stdout if done.returncode == 0 else None


def _state(text: str | None, path: str, scratch: Path) -> DeploymentState:
    """Parse shard *text* with the shard module's own checks; ``None`` is an empty state."""
    name = Path(path).name
    if text is None:
        return DeploymentState(path=scratch / name, object_uuid=Path(path).stem)
    target = scratch / name
    target.write_text(text, encoding="utf-8")
    return DeploymentState.from_file(target)


def _bindings(state: DeploymentState) -> dict[tuple[str, str], str]:
    return {(platform, tenant): value for platform, tenant, value in state.bindings()}


def replay(root: Path, state_commit: str) -> ReplayResult:
    """Apply *state_commit*'s deployment-state delta to the working tree at *root*."""
    result = ReplayResult()
    changed = _git(
        root,
        "diff",
        "--name-only",
        "--no-renames",
        f"{state_commit}^",
        state_commit,
        "--",
        DEPLOYMENT_STATES,
    ).splitlines()
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        for path in (line for line in changed if line.endswith(".json")):
            (scratch / "base").mkdir(exist_ok=True)
            (scratch / "ours").mkdir(exist_ok=True)
            base = _bindings(_state(_blob(root, f"{state_commit}^", path), path, scratch / "base"))
            ours_state = _state(_blob(root, state_commit, path), path, scratch / "ours")
            ours = _bindings(ours_state)
            tip_path = root / path
            tip = (
                DeploymentState.from_file(tip_path)
                if tip_path.is_file()
                else DeploymentState(path=tip_path, object_uuid=Path(path).stem)
            )
            tip_bindings = _bindings(tip)
            for key in sorted(set(base) | set(ours)):
                if base.get(key) == ours.get(key):
                    continue
                platform, tenant = key
                theirs = tip_bindings.get(key)
                if theirs not in (base.get(key), ours.get(key)):
                    result.conflicts.append(
                        f"deployment_state_conflict {path} {platform}/{tenant}: "
                        f"kept {ours.get(key)!r}, the default branch had {theirs!r}"
                    )
                if key in ours:
                    tip.set(platform, tenant, ours[key])
                else:
                    tip.remove(platform, tenant)
            for extra_key, value in ours_state.extra.items():
                tip.extra.setdefault(extra_key, value)
            tip.path.parent.mkdir(parents=True, exist_ok=True)
            tip.save()
            (result.written if tip.platforms else result.removed).append(path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: opentide deploy replay-state <state_commit>", file=sys.stderr)
        return 2
    result = replay(Path.cwd(), args[0])
    for line in result.conflicts:
        print(line, file=sys.stderr)
    print(
        f"Replayed deployment state: {len(result.written)} written, "
        f"{len(result.removed)} removed, {len(result.conflicts)} conflicting"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
