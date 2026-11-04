"""CLI E2E: the changed-files default in a git repository with no commit yet.

Right after ``git init`` and ``opentide setup``, ``HEAD`` names a branch with no
commit. ``deploy`` (without ``--all``, ``--uuid`` or ``--file``), ``validate
query --changed`` and ``lint --changed`` failed there with ``b'HEAD'``, the
repr of the ``KeyError`` Dulwich raises. The last commit is what they read
outside CI; there is none, so nothing changed, and the run says why.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.test_cli.conftest import LOCAL_SHELL_UNSET, without_envelope

pytestmark = pytest.mark.cli_e2e

NO_COMMITS = (
    "HEAD names no commit yet (a new repository or an orphan branch), so no file has changed: "
)


@pytest.fixture
def unborn_corpus(tide_corpus_repo: Path, git_home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The corpus, uncommitted in a fresh ``git init``, run from a user's shell."""
    del git_home
    for name in LOCAL_SHELL_UNSET:
        monkeypatch.delenv(name, raising=False)
    subprocess.run(["git", "init", "-q"], cwd=tide_corpus_repo, check=True, capture_output=True)
    return tide_corpus_repo


def _no_key_repr(output: str) -> None:
    assert "b'HEAD'" not in output
    assert "Traceback" not in output


@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
def test_deploy_without_commits_reads_no_rule_and_says_why(
    invoke_cli, unborn_corpus: Path, refuse_deployment_engines: list[str], json_output: bool
) -> None:
    result = invoke_cli(
        "deploy", "--dry-run", "--strategy", "PREVIEW", repo=unborn_corpus, json_output=json_output
    )

    _no_key_repr(result.stdout + result.stderr)
    assert result.exit_code == 0, result.stdout + result.stderr
    assert refuse_deployment_engines == []
    warning = NO_COMMITS + "commit the rules, or pass --all to read every rule file"
    if not json_output:
        assert "Skipped: " in result.stdout
        assert " ".join(result.stderr.split()).count(f"warning: {warning}") == 1
        return
    assert without_envelope(json.loads(result.stdout)) == {
        "strategies": ["PREVIEW"],
        "deployed": [],
        "dry_run": True,
        "plan": {},
        "payloads": {},
        "ok": True,
        "status": "skipped",
        "message": "No rule this run read has a status that maps to its strategies",
        "warnings": [warning],
    }


def test_deploy_all_without_commits_reads_every_rule(
    invoke_cli, unborn_corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--all`` reads no diff: the advice the warning gives works."""

    class _Engines:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return dict.fromkeys(platforms, MagicMock())

    monkeypatch.setattr("opentide.platforms.plugins.EnabledPlatforms", _Engines)
    result = invoke_cli("deploy", "--dry-run", "--strategy", "PREVIEW", "--all", repo=unborn_corpus)

    _no_key_repr(result.stdout + result.stderr)
    payload = json.loads(result.stdout)
    assert payload["plan"], payload
    assert not any(NO_COMMITS in warning for warning in payload.get("warnings", []))


def test_validate_query_changed_without_commits_checks_nothing_and_says_why(
    invoke_cli, unborn_corpus: Path
) -> None:
    result = invoke_cli("validate", "query", "--changed", repo=unborn_corpus)

    _no_key_repr(result.stdout + result.stderr)
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "skipped"
    assert payload["scope"] == "changed"
    assert payload["warnings"] == [
        NO_COMMITS + "commit the rules, or drop --changed to check every rule"
    ]


def test_lint_changed_without_commits_lints_nothing_and_says_why(
    invoke_cli, unborn_corpus: Path
) -> None:
    result = invoke_cli("lint", "--changed", repo=unborn_corpus)

    _no_key_repr(result.stdout + result.stderr)
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["scope"] == "changed"
    assert payload["summary"]["files"] == 0
    assert payload["warnings"] == [
        NO_COMMITS + "commit the files, or drop --changed to lint every object file"
    ]


def test_ci_deploy_without_commits_fails_with_a_sentence(
    invoke_cli, unborn_corpus: Path, refuse_deployment_engines: list[str]
) -> None:
    """In CI the triggering commit must be in the checkout: no commit is a failure."""
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--strategy",
        "RELEASE",
        repo=unborn_corpus,
        extra_env={
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(unborn_corpus),
            "GITHUB_SHA": "0" * 40,
        },
    )

    _no_key_repr(result.stdout + result.stderr)
    assert result.exit_code == 1, result.stdout + result.stderr
    assert refuse_deployment_engines == []
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert payload["failure"]["message"] == (
        f"The git repository at {unborn_corpus.resolve()} has no commits yet"
    )
