"""The PRODUCTION plan diffs against HEAD's first parent (#546).

The base used to be the second commit of a date-ordered walk from HEAD. On a
merge commit that is usually the merged branch's head, so the rules the merge
changed produced no diff and were not deployed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from tests.corpus_support import (
    clear_runtime_caches,
    materialise_corpus,
    real_rules_folder,
    write_rule_variant,
)
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()

FEATURE_RULE_UUID = "00000000-0000-4000-8003-000000000201"
TRUNK_RULE_UUID = "00000000-0000-4000-8003-000000000202"

_HIDDEN = (
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_WORKSPACE",
    "GITHUB_SHA",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "TF_BUILD",
    "BUILD_SOURCESDIRECTORY",
    "BUILD_SOURCEVERSION",
    "CI_PROJECT_DIR",
    "CI_COMMIT_SHA",
    "CI_COMMIT_BEFORE_SHA",
    "DEPLOYMENT_PLAN",
)


def _git(cwd: Path, *args: str, date: str | None = None) -> str:
    env = os.environ.copy()
    if date is not None:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    done = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=env
    )
    return done.stdout.strip()


def _commit(repo: Path, message: str, date: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message, date=date)


def _catalogue(tmp_path: Path) -> tuple[Path, Path]:
    """Configuration and the corpus rules, in a repository of their own.

    Only ``.opentide`` and ``objects/`` are copied. The corpus also keeps
    its legacy ``Objects/`` tree, which a case-insensitive file system (macOS)
    makes the same folder as ``objects/``, so git would record the rules under
    ``Objects/rules`` and no diff path would match the rules folder.
    """
    corpus = materialise_corpus(tmp_path / "corpus")
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copytree(corpus / ".opentide", repo / ".opentide")
    shutil.copytree(real_rules_folder(corpus), repo / "objects" / "rules")
    # Deploy compiles each rule, and compilation resolves the objective and
    # threat a rule references, so they have to travel with the rules.
    for family in ("objectives", "threats"):
        shutil.copytree(corpus / "objects" / family, repo / "objects" / family)
    return repo, repo / "objects" / "rules"


def _merged_catalogue(tmp_path: Path, *, detached: bool) -> tuple[Path, str]:
    """A corpus repository whose HEAD merges a branch newer than the trunk tip.

    The feature branch adds a ``PRODUCTION`` rule. The trunk adds a different
    ``PRODUCTION`` rule after the branch point, with an older commit date than
    the feature head, so a date-ordered walk picks the feature head second.
    """
    repo, rules = _catalogue(tmp_path)
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "catalogue", "2026-01-01T00:00:00+00:00")

    _git(repo, "checkout", "-q", "-b", "feature")
    write_rule_variant(rules, "rule-0201-feature.yaml", FEATURE_RULE_UUID, status="PRODUCTION")
    _commit(repo, "feature rule", "2026-01-03T00:00:00+00:00")

    _git(repo, "checkout", "-q", "main")
    write_rule_variant(rules, "rule-0202-trunk.yaml", TRUNK_RULE_UUID, status="PRODUCTION")
    _commit(repo, "trunk rule", "2026-01-02T00:00:00+00:00")

    if detached:
        # The shape of ``refs/pull/N/merge`` that actions/checkout checks out.
        _git(repo, "checkout", "-q", "--detach", "main")
    _git(
        repo,
        "merge",
        "--no-ff",
        "-q",
        "-m",
        "merge feature",
        "feature",
        date="2026-01-04T00:00:00+00:00",
    )
    return repo, _git(repo, "rev-parse", "HEAD")


def _env(repo: Path, head: str, ci: str = "github") -> dict[str, str | None]:
    env: dict[str, str | None] = {name: None for name in _HIDDEN}
    env.update({"OPENTIDE_REPO_ROOT": str(repo), "OPENTIDE_TIDE_WORKSPACE": str(repo)})
    if ci == "azure":
        env.update(
            {"TF_BUILD": "True", "BUILD_SOURCESDIRECTORY": str(repo), "BUILD_SOURCEVERSION": head}
        )
    else:
        env.update({"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(repo), "GITHUB_SHA": head})
    return env


@pytest.fixture(autouse=True)
def _fresh_registry() -> object:
    clear_runtime_caches()
    yield
    clear_runtime_caches()


@pytest.mark.parametrize("detached", [True, False], ids=["pull-request-merge-ref", "branch-merge"])
def test_production_base_is_the_first_parent(
    tmp_path: Path, git_home: Path, detached: bool
) -> None:
    del git_home
    from opentide.deployment.git_backend import open_repo
    from opentide.deployment.git_repo import _production_base

    repo, _ = _merged_catalogue(tmp_path, detached=detached)

    assert _production_base(open_repo(repo)) == _git(repo, "rev-parse", "HEAD^1")


@pytest.mark.parametrize("ci", ["github", "azure"])
@pytest.mark.parametrize("detached", [True, False], ids=["pull-request-merge-ref", "branch-merge"])
def test_production_plan_deploys_the_rules_a_merge_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, detached: bool, ci: str
) -> None:
    del git_home
    repo, head = _merged_catalogue(tmp_path, detached=detached)
    monkeypatch.chdir(repo)

    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--plan", "PRODUCTION"],
        env=_env(repo, head, ci),
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed", payload
    # Only the merged branch's rule: the trunk rule was already deployed by
    # the trunk's own production run.
    assert payload["plan"] == {"sentinel": [FEATURE_RULE_UUID]}


def test_production_plan_on_the_first_commit_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path
) -> None:
    del git_home
    repo, _ = _catalogue(tmp_path)
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "catalogue", "2026-01-01T00:00:00+00:00")
    monkeypatch.chdir(repo)

    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--plan", "PRODUCTION"],
        env=_env(repo, _git(repo, "rev-parse", "HEAD")),
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "skipped"
    assert payload["plan"] == {}
