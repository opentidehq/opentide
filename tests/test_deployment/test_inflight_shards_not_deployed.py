"""Deploy sends the committed rule file, never another pull request's preview shard."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from tests.corpus_support import (
    clear_runtime_caches,
    materialise_corpus,
    real_rules_folder,
    write_rule_variant,
)
from typer.testing import CliRunner

from opentide.indexing.inflight_change import build_shard_payload

RULE_UUID = "00000000-0000-4000-8003-000000000201"


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    for name in ("CI", "GITHUB_ACTIONS", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "dev")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "dev@example.test")

    corpus = materialise_corpus(tmp_path / "corpus")
    root = tmp_path / "repo"
    root.mkdir()
    shutil.copytree(corpus / ".opentide", root / ".opentide")
    shutil.copytree(real_rules_folder(corpus), root / "objects" / "rules")
    for family in ("objectives", "threats"):
        shutil.copytree(corpus / "objects" / family, root / "objects" / family)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(root))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(root))
    monkeypatch.chdir(root)
    clear_runtime_caches()
    yield root
    clear_runtime_caches()


def test_release_deploy_sends_the_committed_rule_not_an_inflight_shard(repo: Path) -> None:
    """The registry applied every inflight shard, and deploy reads rules from it.

    An open pull request's shard on the default branch, at the same version as
    the rule, replaced it: a RELEASE deploy of a reviewed hotfix to that rule
    shipped the other pull request's unreviewed query instead.
    """
    from opentide.cli import app

    path = write_rule_variant(
        repo / "objects" / "rules", "rule-0201-x.yaml", RULE_UUID, status="PRODUCTION"
    )
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "catalogue")

    # An open pull request rewrote the query; its inflight job published the shard.
    body = yaml.safe_load(path.read_text(encoding="utf-8"))
    body["configurations"]["sentinel"]["query"] = "UNREVIEWED_QUERY | take 1\n"
    inflight = repo / ".opentide" / "inflight"
    inflight.mkdir(parents=True, exist_ok=True)
    shard = build_shard_payload(body, "objects/rules/rule-0201-x.yaml")
    (inflight / f"{RULE_UUID}.json").write_text(json.dumps(shard, default=str), encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "ci: update inflight preview shards [skip ci]")

    # A reviewed hotfix to the same rule merges.
    path.write_text(
        path.read_text(encoding="utf-8").replace("Simulated Sentinel rule", "Hotfixed rule"),
        encoding="utf-8",
    )
    _git(repo, "commit", "-q", "-am", "hotfix")

    result = CliRunner().invoke(app, ["--json", "deploy", "--dry-run", "--strategy", "RELEASE"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["plan"] == {"sentinel": [RULE_UUID]}
    (preview,) = payload["payloads"]["sentinel"]
    properties = preview["api_request"]["properties"]
    assert "UNREVIEWED_QUERY" not in properties["query"]
    assert properties["description"].startswith("Hotfixed rule")
