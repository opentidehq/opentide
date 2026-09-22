"""CLI E2E: git baselines for ``generate docs --changed`` and ``generate inflight``.

Harness gap #268. Changed-object discovery is a git contract, so these run the
installed console script against real repositories: one with no ``HEAD`` at all
(#241) and one whose default branch is ``master`` (#251).
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
from pytest_console_scripts import RunResult, ScriptRunner
from tests.test_cli.e2e.helpers import write_tutorial_objects

pytestmark = [
    pytest.mark.cli_smoke,
    pytest.mark.script_launch_mode("subprocess"),
]


def _env(repo: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(repo)
    for leaked in ("DEPLOYMENT_PLAN", "CI", "GITHUB_ACTIONS", "TF_BUILD", "INFLIGHT_PATHS"):
        env.pop(leaked, None)
    return env


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=e2e@opentide.test", "-c", "user.name=e2e", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _run(script_runner: ScriptRunner, repo: Path, args: Sequence[str]) -> RunResult:
    return script_runner.run(
        ["opentide", "--json", "--repo", str(repo), *args],
        env=_env(repo),
        cwd=str(repo),
        print_result=False,
    )


def _scaffold(script_runner: ScriptRunner, repo: Path) -> None:
    setup = script_runner.run(
        [
            "opentide",
            "--json",
            "setup",
            "--yes",
            "--name",
            "Baseline",
            "--platform",
            "sentinel",
            "--path",
            str(repo),
        ],
        env=_env(repo.parent),
        print_result=False,
    )
    assert setup.returncode == 0, setup.stdout + setup.stderr
    write_tutorial_objects(repo)
    generate = _run(script_runner, repo, ["generate"])
    assert generate.returncode == 0, generate.stdout + generate.stderr


def test_docs_changed_without_git_head_is_structured(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    repo = tmp_path / "no-git"
    _scaffold(script_runner, repo)

    result = _run(script_runner, repo, ["generate", "docs", "--changed"])
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    payload = json.loads(result.stdout.strip())
    assert payload["ok"] is False
    assert payload["status"] == "failed"
    assert "git repository" in payload["message"]


def test_inflight_without_git_head_does_not_traceback(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    repo = tmp_path / "no-git-inflight"
    _scaffold(script_runner, repo)

    result = _run(script_runner, repo, ["generate", "inflight"])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert json.loads(result.stdout.strip())["phase"] == "inflight"


def test_changed_objects_resolve_against_a_master_default_branch(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """Feature branch off ``master``: docs and inflight must see the committed diff."""
    repo = tmp_path / "master-repo"
    _scaffold(script_runner, repo)

    _git(repo, "init", "-q", "-b", "master", ".")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial catalogue")
    _git(repo, "checkout", "-qb", "feature")

    rule = repo / "objects" / "rules" / "sentinel-kql-rule.yaml"
    text = rule.read_text(encoding="utf-8")
    assert "version: 1" in text
    rule.write_text(text.replace("version: 1", "version: 2", 1), encoding="utf-8")
    _git(repo, "commit", "-qam", "bump rule version")

    docs = _run(script_runner, repo, ["generate", "docs", "--changed"])
    assert docs.returncode == 0, docs.stdout + docs.stderr
    docs_payload = json.loads(docs.stdout.strip())
    assert docs_payload["changed_paths"] == ["objects/rules/sentinel-kql-rule.yaml"], docs_payload
    assert docs_payload["counts"]["rules"] >= 1

    inflight = _run(script_runner, repo, ["generate", "inflight"])
    assert inflight.returncode == 0, inflight.stdout + inflight.stderr
    shards = sorted((repo / ".opentide" / "inflight").glob("*.json"))
    assert shards, "expected an inflight shard for the changed rule"


def test_untracked_object_yaml_counts_as_changed(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    repo = tmp_path / "untracked-repo"
    _scaffold(script_runner, repo)
    _git(repo, "init", "-q", "-b", "development", ".")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial catalogue")
    _git(repo, "checkout", "-qb", "feature")

    source = repo / "objects" / "rules" / "sentinel-kql-rule.yaml"
    new_rule = repo / "objects" / "rules" / "second-rule.yaml"
    new_rule.write_text(
        source.read_text(encoding="utf-8")
        .replace("00000000-0000-4000-8003-000000000001", "00000000-0000-4000-8003-000000000099")
        .replace("Sentinel KQL Rule", "Second Sentinel Rule"),
        encoding="utf-8",
    )

    docs = _run(script_runner, repo, ["generate", "docs", "--changed"])
    assert docs.returncode == 0, docs.stdout + docs.stderr
    payload = json.loads(docs.stdout.strip())
    assert "objects/rules/second-rule.yaml" in payload["changed_paths"], payload


def test_a_workspace_nested_in_the_checkout_still_sees_its_changes(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """Client repos often keep the tide workspace in a subdirectory.

    git prints ``detections/objects/...`` there; joining that onto the workspace
    root, or matching it against ``^objects/``, silently loses every change.
    """
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    repo = checkout / "detections"
    _scaffold(script_runner, repo)
    _git(checkout, "init", "-q", "-b", "main", ".")
    _git(checkout, "add", "-A")
    _git(checkout, "commit", "-qm", "initial catalogue")
    _git(checkout, "checkout", "-qb", "feature")

    rule = repo / "objects" / "rules" / "sentinel-kql-rule.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("version: 1", "version: 2", 1), encoding="utf-8"
    )

    docs = _run(script_runner, repo, ["generate", "docs", "--changed"])
    assert docs.returncode == 0, docs.stdout + docs.stderr
    payload = json.loads(docs.stdout.strip())
    assert payload["counts"]["rules"] >= 1, payload
    assert [Path(p).name for p in payload["changed_paths"]] == ["sentinel-kql-rule.yaml"], payload

    inflight = _run(script_runner, repo, ["generate", "inflight"])
    assert inflight.returncode == 0, inflight.stdout + inflight.stderr
    shards = sorted((repo / ".opentide" / "inflight").glob("*.json"))
    assert shards, "a nested workspace must still produce an inflight shard"


def _bump_rule(repo: Path) -> None:
    rule = repo / "objects" / "rules" / "sentinel-kql-rule.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("version: 1", "version: 2", 1), encoding="utf-8"
    )


def _published_feature_branch(script_runner: ScriptRunner, tmp_path: Path) -> tuple[Path, Path]:
    """A repo whose ``feature`` branch is pushed with ``-u``, so it tracks itself."""
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    repo = tmp_path / "pushed"
    _scaffold(script_runner, repo)
    _git(repo, "init", "-q", "-b", "main", ".")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial catalogue")
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "-u", "origin", "main")
    _git(repo, "checkout", "-qb", "feature")
    _bump_rule(repo)
    _git(repo, "commit", "-qam", "bump rule version")
    _git(repo, "push", "-q", "-u", "origin", "feature")
    return origin, repo


def test_a_pushed_feature_branch_still_compares_against_the_default_branch(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """``@{upstream}`` was tried first; after ``push -u`` that is the branch itself.

    ``merge-base HEAD origin/feature`` is ``HEAD``, so every committed change
    vanished and ``generate inflight`` wrote nothing for a pushed branch.
    """
    _, repo = _published_feature_branch(script_runner, tmp_path)

    docs = _run(script_runner, repo, ["generate", "docs", "--changed"])
    assert docs.returncode == 0, docs.stdout + docs.stderr
    payload = json.loads(docs.stdout.strip())
    assert payload["changed_paths"] == ["objects/rules/sentinel-kql-rule.yaml"], payload

    inflight = _run(script_runner, repo, ["generate", "inflight"])
    assert inflight.returncode == 0, inflight.stdout + inflight.stderr
    assert sorted((repo / ".opentide" / "inflight").glob("*.json")), "no shard for a pushed branch"


def test_a_ci_checkout_of_the_pr_branch_finds_its_changes(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """``actions/checkout`` runs ``checkout -B <branch> refs/remotes/origin/<branch>``.

    That sets the branch's upstream to its own remote copy, which is how the
    generated inflight job came to find no changes on every pull request.
    """
    origin, _ = _published_feature_branch(script_runner, tmp_path)
    ci = tmp_path / "ci"
    ci.mkdir()
    _git(ci, "init", "-q", ".")
    _git(ci, "remote", "add", "origin", str(origin))
    _git(ci, "fetch", "-q", "origin", "+refs/heads/*:refs/remotes/origin/*")
    _git(ci, "checkout", "-q", "--force", "-B", "feature", "refs/remotes/origin/feature")

    inflight = _run(script_runner, ci, ["generate", "inflight"])
    assert inflight.returncode == 0, inflight.stdout + inflight.stderr
    assert sorted((ci / ".opentide" / "inflight").glob("*.json")), "the PR job found no changes"


def test_non_ascii_object_filenames_are_not_dropped(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """git C-quotes non-ASCII paths (``"d\\303\\251tection.yaml"``) unless asked not to."""
    repo = tmp_path / "unicode-repo"
    _scaffold(script_runner, repo)
    _git(repo, "init", "-q", "-b", "main", ".")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial catalogue")
    _git(repo, "checkout", "-qb", "feature")

    source = repo / "objects" / "rules" / "sentinel-kql-rule.yaml"
    renamed = repo / "objects" / "rules" / "détection-règle.yaml"
    renamed.write_text(
        source.read_text(encoding="utf-8")
        .replace("00000000-0000-4000-8003-000000000001", "00000000-0000-4000-8003-000000000077")
        .replace("Sentinel KQL Rule", "Règle Sentinel"),
        encoding="utf-8",
    )

    docs = _run(script_runner, repo, ["generate", "docs", "--changed"])
    assert docs.returncode == 0, docs.stdout + docs.stderr
    payload = json.loads(docs.stdout.strip())
    assert payload["changed_paths"] == ["objects/rules/détection-règle.yaml"], payload

    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add a rule with a French name")
    inflight = _run(script_runner, repo, ["generate", "inflight"])
    assert inflight.returncode == 0, inflight.stdout + inflight.stderr
    shard = repo / ".opentide" / "inflight" / "00000000-0000-4000-8003-000000000077.json"
    assert shard.is_file(), sorted(p.name for p in (repo / ".opentide" / "inflight").glob("*"))
