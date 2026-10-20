"""A RELEASE deploy retires DISABLED and REMOVED rules by default (#548).

The deployment spec defines ``DISABLEMENT`` as "any active deployment of the
rule is disabled" and ``DELETION`` as removal from the platform, and a
``RELEASE`` run acts on both. ``--keep-deprecated`` defaulted to off, so those
rules were dropped before the strategy was consulted and a retirement never
reached the platform. It now defaults on, and off only with ``--all``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_cli.test_deploy_production_base import _catalogue, _commit, _env, _git
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.deploy import keeps_deprecated

runner = CliRunner()

SENTINEL_RULE = "00000000-0000-4000-8003-000000000001"


def _retire(tmp_path: Path, status: str) -> tuple[Path, str]:
    repo, rules = _catalogue(tmp_path)
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "catalogue", "2026-01-01T00:00:00+00:00")
    rule = rules / "rule-0001-sentinel-kql.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("status: STAGING", f"status: {status}"),
        encoding="utf-8",
    )
    _commit(repo, f"retire the Sentinel rule as {status}", "2026-01-02T00:00:00+00:00")
    return repo, _git(repo, "rev-parse", "HEAD")


@pytest.fixture(autouse=True)
def _fresh_registry() -> object:
    from tests.corpus_support import clear_runtime_caches

    clear_runtime_caches()
    yield
    clear_runtime_caches()


@pytest.mark.parametrize("status", ["DISABLED", "REMOVED"])
def test_release_run_deploys_a_retired_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, status: str
) -> None:
    del git_home
    repo, head = _retire(tmp_path, status)
    monkeypatch.chdir(repo)

    result = runner.invoke(
        app, ["--json", "deploy", "--dry-run", "--strategy", "RELEASE"], env=_env(repo, head)
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["plan"] == {"sentinel": [SENTINEL_RULE]}


@pytest.mark.parametrize("status", ["DISABLED", "REMOVED"])
def test_preview_run_never_retires_a_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, status: str
) -> None:
    """Only a RELEASE run acts on DISABLEMENT and DELETION rules."""
    del git_home
    repo, head = _retire(tmp_path, status)
    monkeypatch.chdir(repo)

    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", "PREVIEW", "--keep-deprecated"],
        env=_env(repo, head),
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "skipped"
    assert payload["plan"] == {}


def test_drop_deprecated_leaves_retired_rules_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path
) -> None:
    del git_home
    repo, head = _retire(tmp_path, "REMOVED")
    monkeypatch.chdir(repo)

    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", "RELEASE", "--drop-deprecated"],
        env=_env(repo, head),
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "skipped"
    assert payload["plan"] == {}


@pytest.mark.parametrize(
    ("all_files", "requested", "expected"),
    [
        (False, None, True),
        (True, None, False),
        (False, False, False),
        (True, True, True),
    ],
    ids=["diff", "all", "diff-drop-deprecated", "all-keep-deprecated"],
)
def test_keep_deprecated_defaults_on_unless_every_rule_file_is_read(
    all_files: bool, requested: bool | None, expected: bool
) -> None:
    assert keeps_deprecated(all_files, requested) is expected


def test_every_rule_file_leaves_the_retired_catalogue_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path
) -> None:
    """``--all`` must not disable or delete every retired rule by accident."""
    del git_home
    repo, head = _retire(tmp_path, "REMOVED")
    monkeypatch.chdir(repo)

    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", "RELEASE", "--all"],
        env=_env(repo, head),
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert SENTINEL_RULE not in payload["plan"].get("sentinel", [])

    kept = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", "RELEASE", "--all", "--keep-deprecated"],
        env=_env(repo, head),
    )
    assert kept.exit_code == 0, kept.stdout + kept.stderr
    assert SENTINEL_RULE in json.loads(kept.stdout)["plan"]["sentinel"]
