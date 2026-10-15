"""The generated production job commits its deploy write-backs (#548).

A production deploy rewrites promoted rule statuses and records vendor ids
under ``.opentide/states/deployment/``. The generated job must commit both to
the default branch, skip CI on that commit, retry a rejected push, and do
nothing when the deploy changed nothing. It must also commit what a deploy
that failed part way recorded, and still fail the job.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from opentide.ci.azure import WRITEBACK_CONDITION, render_azure
from opentide.ci.github import WRITEBACK_IF, render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.inflight import GITLAB_INSTALL_GIT
from opentide.ci.models import CiRenderOptions
from opentide.ci.writeback import (
    DEPLOY_FAILED_NOTE,
    DEPLOYMENT_STATES,
    WRITEBACK_EMPTY_NOTE,
    WRITEBACK_MESSAGE,
    WRITEBACK_RULES_SKIPPED,
    deploy_then_writeback,
    production_writeback,
    rules_folder,
)

DEPLOY = "opentide deploy --plan PRODUCTION --keep-deprecated --skip-unconfigured"
GITLAB_PUSH = (
    'git push "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/'
    '${CI_PROJECT_PATH}.git" "HEAD:$CI_DEFAULT_BRANCH"'
)


def _options(ci: str, **overrides: object) -> CiRenderOptions:
    values: dict[str, object] = {"ci": ci, "platforms": ["sentinel"], "default_branch": "main"}
    values.update(overrides)
    return CiRenderOptions(**values)  # type: ignore[arg-type]


def _azure_job(name: str) -> dict:
    parsed = yaml.safe_load(render_azure(_options("azure")))
    for stage in parsed["stages"]:
        for job in stage.get("jobs", []):
            if job.get("job") == name:
                return job
    raise AssertionError(f"no Azure job {name}")


def _assert_writeback(script: str, *, push: str) -> None:
    assert f'git commit -m "{WRITEBACK_MESSAGE}"' in script
    assert "[skip ci]" in WRITEBACK_MESSAGE
    assert f"git add -- {DEPLOYMENT_STATES}" in script
    assert 'opentide validate --strict "$@"' in script
    assert "git add -u -- objects/rules" in script
    assert "if git diff --staged --quiet; then" in script
    assert f"until {push}; do" in script
    assert "git rebase FETCH_HEAD" in script
    # The shards are staged before the rule files are validated.
    assert script.index(DEPLOYMENT_STATES) < script.index("opentide validate --strict")


# --- Rendered jobs -----------------------------------------------------------


def test_github_writeback_runs_whenever_the_deploy_started() -> None:
    job = yaml.safe_load(render_github(_options("github")))["jobs"]["deploy_production"]
    assert job["permissions"] == {"contents": "write"}
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    deploy = steps[names.index("Deploy")]
    assert deploy["id"] == "deploy"
    assert deploy["run"] == DEPLOY
    writeback = steps[names.index("Commit deployment write-backs")]
    assert writeback is steps[-1]
    assert writeback["if"] == WRITEBACK_IF
    assert "!cancelled()" in WRITEBACK_IF
    assert "steps.deploy.outcome != 'skipped'" in WRITEBACK_IF
    _assert_writeback(writeback["run"], push='git push origin "HEAD:main"')
    assert 'git config user.name "github-actions[bot]"' in writeback["run"]


def test_github_staging_job_does_not_commit() -> None:
    job = yaml.safe_load(render_github(_options("github")))["jobs"]["deploy_staging"]
    assert "permissions" not in job
    assert not any("git commit" in step.get("run", "") for step in job["steps"])


def test_gitlab_deploy_and_writeback_share_one_block() -> None:
    job = yaml.safe_load(render_gitlab(_options("gitlab")))["deploy_production"]
    assert job["before_script"][0] == GITLAB_INSTALL_GIT
    script = job["script"]
    assert script[0] == "opentide deploy --dry-run --plan PRODUCTION --keep-deprecated"
    block = script[-1]
    assert block.startswith("deploy_status=0\n")
    assert f"{DEPLOY} || deploy_status=$?" in block
    assert block.rstrip().endswith('exit "$writeback_exit"')
    assert 'exit "$deploy_status"' in block
    _assert_writeback(block, push=GITLAB_PUSH)
    staging = yaml.safe_load(render_gitlab(_options("gitlab")))["deploy_staging"]
    assert not any("git commit" in str(line) for line in staging["script"])


def test_azure_writeback_step_runs_after_a_failed_deploy() -> None:
    steps = _azure_job("deploy_production")["steps"]
    assert steps[0] == {"checkout": "self", "persistCredentials": True, "fetchDepth": 0}
    deploy = steps[-2]["script"]
    started = deploy.index("##vso[task.setvariable variable=OPENTIDE_DEPLOY_STARTED]true")
    assert deploy.index("--dry-run") < started < deploy.index(DEPLOY)
    writeback = steps[-1]
    assert writeback["displayName"] == "Commit deployment write-backs"
    assert writeback["condition"] == WRITEBACK_CONDITION
    assert "succeededOrFailed()" in WRITEBACK_CONDITION
    _assert_writeback(writeback["script"], push="git push origin HEAD:main")
    staging = _azure_job("deploy_staging")
    assert not any("git commit" in str(step.get("script", "")) for step in staging["steps"])


@pytest.mark.parametrize("render", [render_github, render_gitlab, render_azure])
def test_production_deploys_disabled_and_removed_rules(render) -> None:
    rendered = render(_options(render.__name__.removeprefix("render_")))
    assert "opentide deploy --dry-run --plan PRODUCTION --keep-deprecated" in rendered
    assert DEPLOY in rendered
    assert "--plan STAGING --keep-deprecated" not in rendered


@pytest.mark.parametrize("render", [render_github, render_gitlab, render_azure])
@pytest.mark.parametrize(
    "overrides",
    [{}, {"explorer_pages": True}, {"sharing": True, "staging": False, "inflight": False}],
    ids=["default", "explorer", "minimal"],
)
def test_pipeline_ends_with_one_newline(render, overrides: dict[str, object]) -> None:
    rendered = render(_options(render.__name__.removeprefix("render_"), **overrides))
    assert rendered.endswith("\n")
    assert not rendered.endswith("\n\n")


def test_rules_folder_comes_from_the_workspace_configuration(tmp_path: Path) -> None:
    config = tmp_path / ".opentide" / "configurations"
    config.mkdir(parents=True)
    (config / "paths.toml").write_text(
        '[paths.objects]\nrule = "Objects/Detection Rules/"\n', encoding="utf-8"
    )
    assert rules_folder(tmp_path) == "Objects/Detection Rules"
    rendered = render_github(_options("github", repo=tmp_path))
    assert "git add -u -- 'Objects/Detection Rules'" in rendered


def test_rules_folder_defaults_without_a_checkout(tmp_path: Path) -> None:
    assert rules_folder(None) == "objects/rules"
    assert rules_folder(tmp_path) == "objects/rules"


# --- The scripts themselves, against real repositories -----------------------

#: Stands in for the CLI. ``deploy`` records a vendor id, promotes the rule and
#: exits ``FAKE_DEPLOY_EXIT``; ``validate`` logs its arguments and exits
#: ``FAKE_VALIDATE_EXIT``.
FAKE_OPENTIDE = """#!/bin/sh
case "$1" in
  deploy)
    mkdir -p .opentide/states/deployment
    printf '{"rule_id": 3}\\n' > .opentide/states/deployment/rule.json
    printf 'status: PRODUCTION\\n' > objects/rules/rule.yaml
    exit "${FAKE_DEPLOY_EXIT:-0}"
    ;;
  validate)
    shift
    echo "$*" >> "$FAKE_VALIDATE_LOG"
    exit "${FAKE_VALIDATE_EXIT:-0}"
    ;;
esac
exit 2
"""


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


@pytest.fixture
def git_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [key for key in os.environ if key.startswith("GIT_")]:
        monkeypatch.delenv(name)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "ci")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "ci@example.test")


@pytest.fixture
def fake_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cli = bin_dir / "opentide"
    cli.write_text(FAKE_OPENTIDE, encoding="utf-8")
    cli.chmod(cli.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "validate.log"
    log.touch()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_VALIDATE_LOG", str(log))
    return log


@pytest.fixture
def clone(tmp_path: Path, git_identity: None, fake_cli: Path) -> Path:
    del git_identity, fake_cli
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    seed = tmp_path / "seed"
    _git(tmp_path, "clone", "-q", str(remote), str(seed))
    (seed / "objects" / "rules").mkdir(parents=True)
    (seed / "objects" / "rules" / "rule.yaml").write_text("status: STAGING\n", encoding="utf-8")
    (seed / "README.md").write_text("catalogue\n", encoding="utf-8")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-q", "-m", "catalogue")
    _git(seed, "push", "-q", "origin", "HEAD:main")
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(remote), str(work))
    return work


def _bash(script: str, cwd: Path, **env: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    assert bash is not None
    return subprocess.run(
        [bash, "-eo", "pipefail", "-c", script],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **env},
    )


def _writeback(work: Path, **env: str) -> subprocess.CompletedProcess[str]:
    script = production_writeback(
        rules="objects/rules",
        push='git push -q origin "HEAD:main"',
        fetch="git fetch -q origin main",
    )
    return _bash(script, work, **env)


def _gitlab_block(work: Path, **env: str) -> subprocess.CompletedProcess[str]:
    script = deploy_then_writeback(
        deploy="opentide deploy --plan PRODUCTION",
        rules="objects/rules",
        push='git push -q origin "HEAD:main"',
        fetch="git fetch -q origin main",
    )
    return _bash(script, work, **env)


def _deploy(work: Path) -> None:
    """What the fake deploy writes, for the separate-step providers."""
    subprocess.run(["opentide", "deploy"], cwd=work, check=False)


def _remote_log(work: Path) -> list[str]:
    _git(work, "fetch", "-q", "origin", "main")
    return _git(work, "log", "--format=%s", "FETCH_HEAD").splitlines()


def _remote_files(work: Path) -> list[str]:
    return sorted(_git(work, "show", "--name-only", "--format=", "FETCH_HEAD").splitlines())


def test_nothing_to_write_back_is_a_no_op(clone: Path, fake_cli: Path) -> None:
    result = _writeback(clone)
    assert result.returncode == 0, result.stderr
    assert WRITEBACK_EMPTY_NOTE in result.stdout
    assert _remote_log(clone) == ["catalogue"]
    assert fake_cli.read_text(encoding="utf-8") == ""


def test_writebacks_land_on_the_default_branch(clone: Path, fake_cli: Path) -> None:
    _deploy(clone)
    (clone / "objects" / "rules" / "stray.yaml").write_text("untracked\n", encoding="utf-8")
    (clone / "README.md").write_text("changed outside the write-back\n", encoding="utf-8")

    result = _writeback(clone)

    assert result.returncode == 0, result.stderr
    assert _remote_log(clone) == [WRITEBACK_MESSAGE, "catalogue"]
    assert _remote_files(clone) == [f"{DEPLOYMENT_STATES}/rule.json", "objects/rules/rule.yaml"]
    # Validation is scoped to the rule files the deploy modified.
    assert fake_cli.read_text(encoding="utf-8").splitlines() == [
        "--strict --file objects/rules/rule.yaml"
    ]


def test_invalid_rule_files_still_commit_the_state(clone: Path) -> None:
    _deploy(clone)

    result = _writeback(clone, FAKE_VALIDATE_EXIT="1")

    assert result.returncode == 1
    assert WRITEBACK_RULES_SKIPPED in result.stderr
    assert _remote_log(clone) == [WRITEBACK_MESSAGE, "catalogue"]
    assert _remote_files(clone) == [f"{DEPLOYMENT_STATES}/rule.json"]


def test_a_rejected_push_is_retried_on_the_new_tip(clone: Path, tmp_path: Path) -> None:
    other = tmp_path / "other"
    _git(tmp_path, "clone", "-q", str(tmp_path / "remote.git"), str(other))
    (other / "README.md").write_text("moved on\n", encoding="utf-8")
    _git(other, "commit", "-q", "-am", "newer merge")
    _git(other, "push", "-q", "origin", "HEAD:main")
    _deploy(clone)

    result = _writeback(clone)

    assert result.returncode == 0, result.stderr
    assert _remote_log(clone) == [WRITEBACK_MESSAGE, "newer merge", "catalogue"]


def test_a_partly_failed_deploy_commits_its_ids_and_still_fails(clone: Path) -> None:
    """GitLab: the deploy records an id, then fails on a later rule."""
    result = _gitlab_block(clone, FAKE_DEPLOY_EXIT="3")

    assert result.returncode == 3, result.stderr
    assert DEPLOY_FAILED_NOTE.replace("$deploy_status", "3") in result.stderr
    assert _remote_log(clone) == [WRITEBACK_MESSAGE, "catalogue"]
    assert _remote_files(clone) == [f"{DEPLOYMENT_STATES}/rule.json", "objects/rules/rule.yaml"]


def test_a_successful_deploy_block_exits_0(clone: Path) -> None:
    result = _gitlab_block(clone)
    assert result.returncode == 0, result.stderr
    assert _remote_log(clone) == [WRITEBACK_MESSAGE, "catalogue"]


def test_a_failed_rebase_fails_the_block_instead_of_pushing_nothing(
    clone: Path, tmp_path: Path
) -> None:
    """``set -e`` is ignored inside a tested subshell; the block must not rely on that."""
    other = tmp_path / "other"
    _git(tmp_path, "clone", "-q", str(tmp_path / "remote.git"), str(other))
    (other / "objects" / "rules" / "rule.yaml").write_text("status: DISABLED\n", encoding="utf-8")
    _git(other, "commit", "-q", "-am", "conflicting edit")
    _git(other, "push", "-q", "origin", "HEAD:main")

    result = _gitlab_block(clone)

    assert result.returncode != 0
    assert _remote_log(clone) == ["conflicting edit", "catalogue"]
