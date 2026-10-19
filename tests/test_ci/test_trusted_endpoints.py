"""Pull-request jobs must not send CI credentials to a tenant URL from the PR."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from opentide.ci.azure import render_azure
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import NO_REVIEWED_CONFIG_NOTE, trusted_platform_config_commands
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
    assert validate[-3:-1] == ["opentide validate --strict", "opentide lint --strict"]
    restore = trusted_platform_config_commands("development")
    assert validate[-1].splitlines() == [
        *restore,
        "opentide validate query --platform elastic --live",
        "opentide validate query --platform splunk --live",
    ]
    assert _runs(jobs["deploy_staging"]["steps"])[-1].splitlines() == [
        *restore,
        "opentide deploy --dry-run --plan STAGING",
        "opentide deploy --plan STAGING --skip-unconfigured",
    ]
    production = "\n".join(_runs(jobs["deploy_production"]["steps"]))
    assert REMOVE not in production
    assert "AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}" in workflow


def test_github_validate_job_without_live_queries_restores_nothing() -> None:
    workflow = render_github(CiRenderOptions(ci="github", platforms=["crowdstrike"]))
    validate = _runs(yaml.safe_load(workflow)["jobs"]["validate"]["steps"])
    assert validate[-2:] == ["opentide validate --strict", "opentide lint --strict"]
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
    assert query["script"] == [*restore, "opentide validate query --platform elastic --live"]
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
    restore = "\n".join(trusted_platform_config_commands("main"))
    query = jobs["validate_query_elastic"]
    assert restore in _azure_script(query)
    # The restore fetches, so the token is kept; one path needs no full history.
    assert query["steps"][0] == {"checkout": "self", "persistCredentials": True}
    staging = jobs["deploy_staging"]
    assert restore in _azure_script(staging)
    assert staging["steps"][0] == {"checkout": "self", "persistCredentials": True, "fetchDepth": 0}
    # Jobs that rebase or diff still ask for full history explicitly.
    for name in ("deploy_production", "inflight_shards", "inflight_prune"):
        assert jobs[name]["steps"][0]["fetchDepth"] == 0, name
    assert REMOVE not in _azure_script(jobs["validate"])
    assert REMOVE not in _azure_script(jobs["deploy_production"])


# --- The commands in a real checkout ------------------------------------------

REVIEWED = 'url = "https://splunk.reviewed.example"\n'
ATTACKER = 'url = "https://attacker.example"\n'
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


def _branches(remote: Path, *, reviewed: bool) -> None:
    seed = remote.parent / "seed"
    _commit(seed, {SPLUNK: REVIEWED} if reviewed else {Path("README.md"): "rules\n"}, "base")
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


def _run(work: Path) -> subprocess.CompletedProcess[str]:
    """The restore, then a command standing in for the credentialed one."""
    bash = shutil.which("bash")
    assert bash is not None
    script = "\n".join([*trusted_platform_config_commands("main"), "touch credentialed"])
    return subprocess.run(
        [bash, "-e", "-c", script], cwd=work, capture_output=True, text=True, check=False
    )


def test_a_full_clone_stays_full_and_keeps_its_merge_base(remote: Path) -> None:
    """``--depth`` here made the staging deploy fail to find the merge base."""
    _branches(remote, reviewed=True)
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
    _branches(remote, reviewed=True)
    work = _checkout(remote, shallow=True)

    done = _run(work)

    assert done.returncode == 0, done.stderr
    assert (work / SPLUNK).read_text(encoding="utf-8") == REVIEWED
    assert not (work / PR_ONLY).exists()
    assert _git(work, "rev-parse", "--is-shallow-repository") == "true"
    assert _git(work, "rev-list", "--count", "FETCH_HEAD") == "1"


def test_without_a_reviewed_configuration_nothing_uses_credentials(remote: Path) -> None:
    """The pull request that adds the configuration has nothing to restore."""
    _branches(remote, reviewed=False)
    work = _checkout(remote, shallow=False)

    done = _run(work)

    assert done.returncode == 0, done.stderr
    assert NO_REVIEWED_CONFIG_NOTE in done.stdout
    assert "pathspec" not in done.stderr
    assert not (work / ".opentide" / "configurations").exists()
    assert not (work / "credentialed").exists()


def _runs(steps: list[dict[str, object]]) -> list[str]:
    return [run for step in steps if isinstance(run := step.get("run"), str)]


def _azure_script(job: dict[str, object]) -> str:
    steps = job["steps"]
    assert isinstance(steps, list)
    scripts = [
        step["script"]
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("script"), str)
    ]
    assert scripts
    return "\n".join(scripts)
