"""Pull-request jobs must not send CI credentials to a tenant URL from the PR."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from opentide.ci.azure import render_azure
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import (
    NO_REVIEWED_CONFIG_NOTE,
    NO_REVIEWED_TENANT_NOTE,
    object_validate_commands,
    reviewed_query_validation_command,
    trusted_platform_config_commands,
)
from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS
from opentide.core.root import get_data_root
from opentide.deployment.git_backend import open_repo

RESTORE = "git checkout FETCH_HEAD -- .opentide/configurations"
REMOVE = "rm -rf -- .opentide/configurations"


def test_commands_replace_the_whole_configuration_tree() -> None:
    assert trusted_platform_config_commands("main") == [
        REMOVE,
        'if [ "$(git rev-parse --is-shallow-repository)" = true ]; '
        "then git fetch --depth=1 origin main; else git fetch origin main; fi",
        "if ! git cat-file -e FETCH_HEAD:.opentide/configurations 2>/dev/null; "
        f'then echo "{NO_REVIEWED_CONFIG_NOTE}"; exit 0; fi',
        RESTORE,
    ]


def test_branch_name_cannot_break_out_of_the_shell() -> None:
    branch = "main; curl https://evil.example"
    quoted = "git fetch origin 'main; curl https://evil.example'"
    github = render_github(
        CiRenderOptions(ci="github", platforms=["splunk"], default_branch=branch)
    )
    azure = render_azure(CiRenderOptions(ci="azure", platforms=["splunk"], default_branch=branch))
    assert quoted in github
    assert quoted in azure


def test_github_secret_jobs_pin_endpoints_and_production_does_not() -> None:
    workflow = render_github(
        CiRenderOptions(
            ci="github",
            platforms=["elastic", "splunk"],
            staging=True,
            default_branch="development",
        )
    )
    jobs = yaml.safe_load(workflow)["jobs"]
    validate = _runs(jobs["validate"]["steps"])
    # The catalogue gate reads the pull request's own configuration; only the
    # step that sends credentials restores the default branch's copy.
    assert validate[-3:-1] == object_validate_commands("sarif")
    restore = trusted_platform_config_commands("development")
    assert validate[-1].splitlines() == [
        *restore,
        reviewed_query_validation_command("elastic"),
        reviewed_query_validation_command("splunk"),
    ]
    assert _runs(jobs["deploy_staging"]["steps"])[-1].splitlines() == [
        *restore,
        "opentide deploy --dry-run --strategy PREVIEW",
        "opentide deploy --strategy PREVIEW --skip-unconfigured",
    ]
    production = "\n".join(_runs(jobs["deploy_production"]["steps"]))
    assert REMOVE not in production
    assert "AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}" in workflow


def test_github_validate_job_without_live_queries_restores_nothing() -> None:
    workflow = render_github(CiRenderOptions(ci="github", platforms=["crowdstrike"]))
    validate = _runs(yaml.safe_load(workflow)["jobs"]["validate"]["steps"])
    assert validate[-2:] == object_validate_commands("sarif")
    assert REMOVE not in "\n".join(validate)


def test_gitlab_query_and_staging_jobs_pin_endpoints() -> None:
    parsed = yaml.safe_load(
        render_gitlab(
            CiRenderOptions(
                ci="gitlab",
                platforms=["sentinel", "elastic"],
                staging=True,
                default_branch="main",
            )
        )
    )
    # GitLab reads its default branch from the project, as the production job does.
    restore = trusted_platform_config_commands('"$CI_DEFAULT_BRANCH"')
    query = parsed["validate_query_elastic"]
    assert "apt-get install -y -qq --no-install-recommends git" in "\n".join(query["before_script"])
    assert query["script"] == [*restore, reviewed_query_validation_command("elastic")]
    # --changed diffs from the merge request base or the previous tip.
    assert query["variables"] == {"GIT_DEPTH": "0"}
    staging = parsed["deploy_staging"]
    assert staging["script"][: len(restore)] == restore
    assert staging["variables"] == {"GIT_DEPTH": "0"}
    assert REMOVE not in "\n".join(parsed["validate"]["script"])
    assert REMOVE not in "\n".join(parsed["deploy_production"]["script"])


def test_azure_query_and_staging_jobs_pin_endpoints() -> None:
    parsed = yaml.safe_load(
        render_azure(
            CiRenderOptions(
                ci="azure",
                platforms=["elastic"],
                staging=True,
                default_branch="main",
            )
        )
    )
    jobs = {job["job"]: job for stage in parsed["stages"] for job in stage["jobs"]}
    restore = trusted_platform_config_commands("main")
    query = jobs["validate_query_elastic"]
    # One step, so the restore's ``exit 0`` also skips the credentialed commands.
    assert _azure_scripts(query)[-1].splitlines() == [
        "set -e",
        *restore,
        reviewed_query_validation_command("elastic"),
    ]
    # The restore fetches, so the token is kept; --changed diffs, so history is full.
    assert query["steps"][0] == {"checkout": "self", "persistCredentials": True, "fetchDepth": 0}
    staging = jobs["deploy_staging"]
    assert _azure_scripts(staging)[-1].splitlines() == [
        "set -e",
        *restore,
        "opentide deploy --dry-run --strategy PREVIEW",
        "opentide deploy --strategy PREVIEW --skip-unconfigured",
    ]
    assert staging["steps"][0] == {"checkout": "self", "persistCredentials": True, "fetchDepth": 0}
    # Jobs that rebase or diff still ask for full history explicitly.
    for name in ("deploy_production", "inflight_shards", "inflight_prune"):
        assert jobs[name]["steps"][0]["fetchDepth"] == 0, name
    assert REMOVE not in _azure_script(jobs["validate"])
    assert REMOVE not in _azure_script(jobs["deploy_production"])


# --- The commands in a real checkout ------------------------------------------

REVIEWED = '[[tenants]]\nurl = "https://splunk.reviewed.example"\n'
ATTACKER = '[[tenants]]\nurl = "https://attacker.example"\n'
# What ``setup`` writes: the platform enabled, its tenant still commented out.
SCAFFOLD = '[platform]\nenabled = true\n\n# [[tenants]]\n# url = "$SPLUNK_URL"\n'
SPLUNK = Path(".opentide/configurations/platforms/splunk.toml")
PR_ONLY = Path(".opentide/configurations/platforms/elastic.toml")


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _commit(repo: Path, files: dict[Path, str], message: str) -> None:
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def remote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``main`` and a pull request branch that has diverged from it."""
    for name in [key for key in os.environ if key.startswith("GIT_")]:
        monkeypatch.delenv(name)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "ci")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "ci@example.test")
    bare = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(bare))
    seed = tmp_path / "seed"
    _git(tmp_path, "clone", "-q", str(bare), str(seed))
    return bare


def _branches(remote: Path, *, reviewed: str | None) -> None:
    """``reviewed`` is ``splunk.toml`` on ``main``; ``None`` leaves out the configuration."""
    seed = remote.parent / "seed"
    base = {SPLUNK: reviewed} if reviewed is not None else {Path("README.md"): "rules\n"}
    _commit(seed, base, "base")
    _git(seed, "push", "-q", "origin", "HEAD:main")
    _git(seed, "checkout", "-q", "-b", "feature")
    _commit(seed, {SPLUNK: ATTACKER, PR_ONLY: ATTACKER}, "pull request")
    _git(seed, "push", "-q", "origin", "feature")
    # main moves on, so the merge base is not main's tip.
    _git(seed, "checkout", "-q", "main")
    _commit(seed, {Path("CHANGES.md"): "later\n"}, "later on main")
    _git(seed, "push", "-q", "origin", "main")


def _checkout(remote: Path, *, shallow: bool) -> Path:
    work = remote.parent / "work"
    depth = ["--depth=1", "--no-single-branch"] if shallow else []
    _git(remote.parent, "clone", "-q", *depth, f"file://{remote}", str(work))
    _git(work, "checkout", "-q", "feature")
    return work


def _run(work: Path, command: str = "touch credentialed") -> subprocess.CompletedProcess[str]:
    """The restore, then ``command``; the default stands in for a credentialed one."""
    return _bash(work, "\n".join([*trusted_platform_config_commands("main"), command]))


def _bash(cwd: Path, script: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    assert bash is not None
    return subprocess.run(
        [bash, "-e", "-c", script], cwd=cwd, capture_output=True, text=True, check=False
    )


@pytest.fixture
def stub_opentide(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An ``opentide`` on PATH that records its arguments in ``./credentialed``."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "opentide"
    stub.write_text('#!/bin/sh\necho "$*" >> credentialed\n', encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")


def test_a_full_clone_stays_full_and_keeps_its_merge_base(remote: Path) -> None:
    """``--depth`` here made the staging deploy fail to find the merge base."""
    _branches(remote, reviewed=REVIEWED)
    work = _checkout(remote, shallow=False)
    base = _git(work, "merge-base", "origin/main", "origin/feature")

    done = _run(work)

    assert done.returncode == 0, done.stderr
    assert (work / SPLUNK).read_text(encoding="utf-8") == REVIEWED
    assert not (work / PR_ONLY).exists()
    assert (work / "credentialed").exists()
    assert _git(work, "rev-parse", "--is-shallow-repository") == "false"
    assert _git(work, "merge-base", "origin/main", "origin/feature") == base
    found = open_repo(work).merge_base("origin/main", "origin/feature")
    assert [commit.hexsha for commit in found] == [base]


def test_a_shallow_clone_fetches_only_the_tip(remote: Path) -> None:
    _branches(remote, reviewed=REVIEWED)
    work = _checkout(remote, shallow=True)

    done = _run(work)

    assert done.returncode == 0, done.stderr
    assert (work / SPLUNK).read_text(encoding="utf-8") == REVIEWED
    assert not (work / PR_ONLY).exists()
    assert _git(work, "rev-parse", "--is-shallow-repository") == "true"
    assert _git(work, "rev-list", "--count", "FETCH_HEAD") == "1"


def test_without_a_reviewed_configuration_nothing_uses_credentials(remote: Path) -> None:
    """The pull request that adds the configuration has nothing to restore."""
    _branches(remote, reviewed=None)
    work = _checkout(remote, shallow=False)

    done = _run(work)

    assert done.returncode == 0, done.stderr
    assert NO_REVIEWED_CONFIG_NOTE in done.stdout
    assert "pathspec" not in done.stderr
    assert not (work / ".opentide" / "configurations").exists()
    assert not (work / "credentialed").exists()


@pytest.mark.usefixtures("stub_opentide")
def test_the_pull_request_adding_the_first_tenant_skips_live_validation(remote: Path) -> None:
    """``main`` has the scaffold; the live check would fail on the tenant the PR adds."""
    _branches(remote, reviewed=SCAFFOLD)
    work = _checkout(remote, shallow=True)

    done = _run(work, reviewed_query_validation_command("splunk"))

    assert done.returncode == 0, done.stderr
    assert NO_REVIEWED_TENANT_NOTE.format(platform="splunk") in done.stdout
    assert (work / SPLUNK).read_text(encoding="utf-8") == SCAFFOLD
    assert not (work / "credentialed").exists()


@pytest.mark.usefixtures("stub_opentide")
def test_a_reviewed_tenant_is_validated_live(remote: Path) -> None:
    _branches(remote, reviewed=REVIEWED)
    work = _checkout(remote, shallow=True)

    done = _run(work, reviewed_query_validation_command("splunk"))

    assert done.returncode == 0, done.stderr
    assert NO_REVIEWED_TENANT_NOTE.format(platform="splunk") not in done.stdout
    assert (work / "credentialed").read_text(encoding="utf-8") == (
        "validate query --platform splunk --live --changed\n"
    )


@pytest.mark.usefixtures("stub_opentide")
@pytest.mark.parametrize("platform", sorted(QUERY_VALIDATION_PLATFORMS))
def test_only_an_uncommented_tenant_runs_live_validation(platform: str, tmp_path: Path) -> None:
    """Each bundled template, as setup writes it, has no tenant until one is uncommented."""
    template = get_data_root() / "configurations" / "platforms" / f"{platform}.toml"
    scaffold = template.read_text(encoding="utf-8")
    config = tmp_path / ".opentide" / "configurations" / "platforms" / f"{platform}.toml"
    config.parent.mkdir(parents=True)
    command = reviewed_query_validation_command(platform)

    config.write_text(scaffold, encoding="utf-8")
    skipped = _bash(tmp_path, command)
    assert NO_REVIEWED_TENANT_NOTE.format(platform=platform) in skipped.stdout
    assert not (tmp_path / "credentialed").exists()

    uncommented = re.sub(r"^#\s*\[\[tenants\]\]", "[[tenants]]", scaffold, flags=re.MULTILINE)
    config.write_text(uncommented, encoding="utf-8")
    ran = _bash(tmp_path, command)
    assert ran.returncode == 0, ran.stderr
    assert (tmp_path / "credentialed").read_text(encoding="utf-8") == (
        f"validate query --platform {platform} --live --changed\n"
    )


def _runs(steps: list[dict[str, object]]) -> list[str]:
    return [run for step in steps if isinstance(run := step.get("run"), str)]


def _azure_scripts(job: dict[str, object]) -> list[str]:
    steps = job["steps"]
    assert isinstance(steps, list)
    scripts = [
        step["script"]
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("script"), str)
    ]
    assert scripts
    return scripts


def _azure_script(job: dict[str, object]) -> str:
    return "\n".join(_azure_scripts(job))
