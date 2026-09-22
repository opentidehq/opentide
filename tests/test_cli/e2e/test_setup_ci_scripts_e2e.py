"""CLI E2E: the job *scripts* inside generated pipelines have to be runnable.

``test_setup_ci_e2e.py`` proves the rendered pipelines are valid YAML. That is
what let #244 through: ``${{CI_JOB_TOKEN}}`` and an ``&&`` chain that skips
``git commit`` are both perfectly well-formed YAML. These tests read the job
scripts and assert provider-correct variable syntax and commit control flow.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from tests.test_cli.conftest import assert_json_ok

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e

#: GitHub Actions expression syntax. Valid there, inert everywhere else.
GITHUB_EXPRESSION = "${{"


def _render(invoke_cli, tmp_path: Path, ci: str, relpath: str) -> tuple[str, Any]:
    """Scaffold a repo, run ``setup ci``, and return the rendered pipeline."""
    fresh = tmp_path / f"{ci}-detections"
    run_repo_setup(
        RepoSetupOptions(
            path=fresh,
            name="Fresh",
            yes=True,
            platforms=[DetectionPlatform.sentinel],
        )
    )
    run_platforms_setup(
        PlatformsSetupOptions(path=fresh, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    result = invoke_cli("setup", "ci", ci, "--path", str(fresh), "--yes", repo=fresh)
    assert_json_ok(result)
    rendered = (fresh / relpath).read_text(encoding="utf-8")
    return rendered, yaml.safe_load(rendered)


def _script_lines(job_name: str, script: Any) -> list[str]:
    """Every ``script`` entry has to survive YAML round-tripping as a string.

    ``- git commit -m "ci: update ..."`` contains ``": "``, so YAML reads the
    sequence item as a mapping and GitLab rejects the pipeline with "script
    config should be a string or a nested array of strings". Coercing with
    ``str()`` here would hide exactly that, so assert the type instead.
    """
    lines = script if isinstance(script, list) else [script]
    for index, line in enumerate(lines):
        assert isinstance(line, str), (
            f"{job_name}: script[{index}] parsed as {type(line).__name__}, not a string: "
            f"{line!r}. A `: ` inside an unquoted sequence item makes YAML read it "
            "as a mapping."
        )
    return lines


def _gitlab_scripts(parsed: dict[str, Any]) -> dict[str, str]:
    """Job name to its flattened ``script`` body."""
    scripts: dict[str, str] = {}
    for name, job in parsed.items():
        if not isinstance(job, dict) or "script" not in job:
            continue
        scripts[name] = "\n".join(_script_lines(name, job["script"]))
    return scripts


def _azure_jobs(parsed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Job id to job body, across every stage."""
    jobs: dict[str, dict[str, Any]] = {}
    for stage in parsed["stages"]:
        for job in stage["jobs"]:
            jobs[job["job"]] = job
    return jobs


def _azure_script(job: dict[str, Any]) -> str:
    return "\n".join(str(step["script"]) for step in job["steps"] if "script" in step)


def assert_commit_is_reachable(script: str, *, label: str) -> None:
    """The commit must not sit behind an ``&&`` chain that stops before it.

    ``git diff --staged --quiet`` exits 1 when there *are* staged changes, so
    ``git diff --staged --quiet && ... && git commit`` commits in exactly the
    wrong case: never.
    """
    assert "git commit" in script, f"{label}: no commit at all\n{script}"
    assert "git diff --staged --quiet &&" not in script, (
        f"{label}: commit is chained behind the emptiness check with &&\n{script}"
    )
    assert "if git diff --staged --quiet; then" in script, (
        f"{label}: emptiness check is not a guard block\n{script}"
    )
    # Anchor on the guard's own closing `fi`, at the start of a line. A bare
    # `script.index("fi")` matches inside `git config user.email ...`, which
    # precedes the guard in every job and makes the ordering check vacuous.
    guard_start = script.index("if git diff --staged --quiet; then")
    guard_end = script.index("\nfi", guard_start)
    assert script.index("git commit") > guard_end, (
        f"{label}: commit runs inside the emptiness guard\n{script}"
    )
    for line in script.splitlines():
        if "exit 0" in line:
            assert "&&" not in line, f"{label}: `exit 0` in an && chain\n{line}"


def test_gitlab_script_items_are_all_strings(invoke_cli, tmp_path: Path) -> None:
    """GitLab rejects a job whose ``script`` holds anything but strings.

    The inflight jobs used to emit ``- git commit -m "ci: update ..."``, which
    YAML reads as ``{'git commit -m "ci': 'update ...'}``.
    """
    _, parsed = _render(invoke_cli, tmp_path, "gitlab", ".gitlab-ci.yml")
    jobs = _gitlab_scripts(parsed)
    assert "inflight_shards" in jobs and "inflight_prune" in jobs, sorted(jobs)


def test_gitlab_inflight_uses_gitlab_variable_syntax(invoke_cli, tmp_path: Path) -> None:
    """#244: the push URL used GitHub expressions, so it pushed to a literal host."""
    rendered, parsed = _render(invoke_cli, tmp_path, "gitlab", ".gitlab-ci.yml")

    assert GITHUB_EXPRESSION not in rendered, (
        "GitLab does not expand GitHub Actions expressions:\n"
        + "\n".join(line for line in rendered.splitlines() if GITHUB_EXPRESSION in line)
    )
    scripts = _gitlab_scripts(parsed)
    for name in ("inflight_shards", "inflight_prune"):
        script = scripts[name]
        assert "${CI_JOB_TOKEN}" in script, script
        assert "${CI_SERVER_HOST}" in script, script
        assert "${CI_PROJECT_PATH}" in script, script


def test_gitlab_jobs_that_run_git_install_it(invoke_cli, tmp_path: Path) -> None:
    """``python:<ver>-slim`` has no git; the inflight jobs died on their first git step."""
    _, parsed = _render(invoke_cli, tmp_path, "gitlab", ".gitlab-ci.yml")
    git_jobs = []
    for name, script in _gitlab_scripts(parsed).items():
        if not any(line.lstrip().startswith("git ") for line in script.splitlines()):
            continue
        git_jobs.append(name)
        job = parsed[name]
        image = str(job.get("image") or parsed.get("default", {}).get("image", ""))
        if "slim" not in image:
            continue
        setup = "\n".join(_script_lines(name, job.get("before_script", [])))
        assert "apt-get install" in setup and " git" in setup, (
            f"{name} runs git on {image}, which does not ship it:\n{setup}"
        )
    assert {"inflight_shards", "inflight_prune"} <= set(git_jobs), git_jobs


@pytest.mark.parametrize("job_name", ["inflight_shards", "inflight_prune"])
def test_gitlab_inflight_commits_when_shards_change(
    invoke_cli, tmp_path: Path, job_name: str
) -> None:
    _, parsed = _render(invoke_cli, tmp_path, "gitlab", ".gitlab-ci.yml")
    assert_commit_is_reachable(_gitlab_scripts(parsed)[job_name], label=job_name)


@pytest.mark.parametrize("job_name", ["inflight_shards", "inflight_prune"])
def test_azure_inflight_commits_when_shards_change(
    invoke_cli, tmp_path: Path, job_name: str
) -> None:
    """#244: every command was ``&&``-joined, so ``exit 0`` ate the commit."""
    _, parsed = _render(invoke_cli, tmp_path, "azure", "azure-pipelines.yml")
    assert_commit_is_reachable(_azure_script(_azure_jobs(parsed)[job_name]), label=job_name)


def test_azure_uses_no_github_expressions(invoke_cli, tmp_path: Path) -> None:
    rendered, _ = _render(invoke_cli, tmp_path, "azure", "azure-pipelines.yml")
    assert GITHUB_EXPRESSION not in rendered, rendered


def test_azure_job_dependencies_stay_inside_their_stage(invoke_cli, tmp_path: Path) -> None:
    """#244: Deploy-stage jobs declared ``dependsOn: generate``, a Generate job."""
    _, parsed = _render(invoke_cli, tmp_path, "azure", "azure-pipelines.yml")
    for stage in parsed["stages"]:
        same_stage = {job["job"] for job in stage["jobs"]}
        for job in stage["jobs"]:
            depends_on = job.get("dependsOn")
            if depends_on is None:
                continue
            names = depends_on if isinstance(depends_on, list) else [depends_on]
            for name in names:
                assert name in same_stage, (
                    f"job {job['job']} in stage {stage['stage']} depends on {name}, "
                    f"which is not in that stage ({sorted(same_stage)}); "
                    "Azure resolves job dependencies within a stage only"
                )


def test_azure_pushing_jobs_keep_their_credentials(invoke_cli, tmp_path: Path) -> None:
    """A job that pushes needs ``persistCredentials``; Azure drops them by default."""
    _, parsed = _render(invoke_cli, tmp_path, "azure", "azure-pipelines.yml")
    for name, job in _azure_jobs(parsed).items():
        if "git push" not in _azure_script(job):
            continue
        checkouts = [step for step in job["steps"] if "checkout" in step]
        assert checkouts, f"{name} pushes but never checks out with credentials"
        assert checkouts[0].get("persistCredentials") is True, f"{name}: {checkouts[0]}"


def test_azure_scripts_fail_fast(invoke_cli, tmp_path: Path) -> None:
    """Dropping the ``&&`` join must not drop the fail-fast it provided.

    Skipping scripts that lack ``set -e`` would skip the only case worth
    testing, so every multi-command script has to opt in explicitly.
    """
    _, parsed = _render(invoke_cli, tmp_path, "azure", "azure-pipelines.yml")
    checked = 0
    for name, job in _azure_jobs(parsed).items():
        for step in job["steps"]:
            if "script" not in step:
                continue
            script = step["script"]
            assert isinstance(script, str), f"{name}: script is {type(script).__name__}"
            lines = [line for line in script.splitlines() if line.strip()]
            if len(lines) < 2:
                continue
            assert lines[0] == "set -e", (
                f"{name}: multi-command script does not fail fast; "
                f"first line is {lines[0]!r}\n{script}"
            )
            checked += 1
    assert checked, "no multi-command Azure script was checked"


def test_github_keeps_its_own_expression_syntax(invoke_cli, tmp_path: Path) -> None:
    """The negative assertions above must not be applied to the GitHub workflow."""
    rendered, parsed = _render(invoke_cli, tmp_path, "github", ".github/workflows/opentide.yml")
    assert GITHUB_EXPRESSION in rendered
    assert parsed["env"]["OPENTIDE_REPO_ROOT"] == "${{ github.workspace }}"


_GENERATE = "opentide generate inflight"
_NEW_SHARD = ".opentide/inflight/0000-pr.json"
_PR_OBJECT = "objects/rules/pr-only.yaml"
_GITLAB_REMOTE = "https://gitlab-ci-token:job-token@gitlab.example.test/team/detections.git"
_PIPELINES = {
    "github": ".github/workflows/opentide.yml",
    "gitlab": ".gitlab-ci.yml",
    "azure": "azure-pipelines.yml",
}


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _commit(repo: Path, message: str, files: dict[str, str | None]) -> None:
    for relpath, content in files.items():
        path = repo / relpath
        if content is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _pr_job_script(ci: str, parsed: dict[str, Any]) -> str:
    """The shell the PR-triggered shard job runs, minus the package install."""
    if ci == "github":
        steps = parsed["jobs"]["inflight_shards"]["steps"]
        runs = [str(step["run"]) for step in steps if "run" in step]
        script = "\n".join(run for run in runs if "pip install" not in run)
    elif ci == "gitlab":
        script = "\n".join(_script_lines("inflight_shards", parsed["inflight_shards"]["script"]))
    else:
        steps = _azure_jobs(parsed)["inflight_shards"]["steps"]
        script = next(str(s["script"]) for s in steps if "git commit" in str(s.get("script", "")))
    assert _GENERATE in script, script
    return script.replace(_GENERATE, f"printf '{{}}\\n' > {_NEW_SHARD}")


@pytest.fixture
def ci_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A bare ``origin`` with ``main``, isolated from the user's git configuration."""
    home = tmp_path / "home"
    home.mkdir()
    origin = tmp_path / "origin.git"
    for name in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(name)
    env = {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "dev",
        "GIT_AUTHOR_EMAIL": "dev@example.test",
        "GIT_COMMITTER_NAME": "dev",
        "GIT_COMMITTER_EMAIL": "dev@example.test",
        # GitLab pushes to an https URL built from CI variables; point it here.
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"url.{origin}.insteadOf",
        "GIT_CONFIG_VALUE_0": _GITLAB_REMOTE,
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    dev = tmp_path / "dev"
    _git(tmp_path, "clone", "-q", str(origin), str(dev))
    return {"origin": origin, "dev": dev, "tmp": tmp_path}


def _run_pr_job(ci: str, script: str, ci_git: dict[str, Any], branch: str) -> None:
    """Check out *branch* the way the provider does for a PR, then run the job."""
    work = ci_git["tmp"] / f"ci-{ci}"
    _git(ci_git["tmp"], "clone", "-q", str(ci_git["origin"]), str(work))
    if ci == "github":
        _git(work, "checkout", "-q", branch)
    elif ci == "gitlab":
        _git(work, "checkout", "-q", "--detach", f"origin/{branch}")
    else:
        # Azure builds a PR from the merge of the PR into its target.
        _git(work, "checkout", "-q", "--detach", "origin/main")
        _git(work, "merge", "-q", "--no-ff", "-m", "Merge PR", f"origin/{branch}")
    env = dict(os.environ) | {
        "CI_DEFAULT_BRANCH": "main",
        "CI_PROJECT_DIR": str(work),
        "CI_JOB_TOKEN": "job-token",
        "CI_SERVER_HOST": "gitlab.example.test",
        "CI_PROJECT_PATH": "team/detections",
        "BUILD_SOURCESDIRECTORY": str(work),
    }
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, f"{ci} job failed\n{done.stdout}\n{done.stderr}"


def _main_tree(origin: Path) -> set[str]:
    return set(_git(origin, "ls-tree", "-r", "--name-only", "main").splitlines())


@pytest.mark.parametrize("ci", sorted(_PIPELINES))
def test_pr_shard_job_publishes_only_shards_to_the_default_branch(
    invoke_cli, tmp_path: Path, ci_git: dict[str, Any], ci: str
) -> None:
    """The PR job committed on the PR head, then pushed ``HEAD`` to ``main``.

    For a PR that is up to date with ``main`` that push is a fast-forward, so
    every PR run published its unreviewed changes to the default branch. Run
    the generated job against a real remote and check what ``main`` gained.
    """
    _, parsed = _render(invoke_cli, tmp_path, ci, _PIPELINES[ci])
    script = _pr_job_script(ci, parsed)
    dev, origin = ci_git["dev"], ci_git["origin"]
    _commit(dev, "seed", {"README.md": "detections\n", ".opentide/inflight/other.json": "{}\n"})
    _git(dev, "push", "-q", "origin", "main")
    main_before = _git(origin, "rev-parse", "main")
    _git(dev, "checkout", "-q", "-b", "feature")
    _commit(dev, "add a rule", {_PR_OBJECT: "name: unreviewed\n"})
    _git(dev, "push", "-q", "origin", "feature")

    _run_pr_job(ci, script, ci_git, "feature")

    assert _git(origin, "rev-parse", "main~1") == main_before, "main gained more than one commit"
    changed = _git(origin, "diff", "--name-only", main_before, "main").splitlines()
    assert changed == [_NEW_SHARD]
    assert _PR_OBJECT not in _main_tree(origin)
    assert _git(origin, "rev-parse", "feature") != _git(origin, "rev-parse", "main")


@pytest.mark.parametrize("ci", sorted(_PIPELINES))
def test_pr_shard_job_starts_from_the_default_branch_shards(
    invoke_cli, tmp_path: Path, ci_git: dict[str, Any], ci: str
) -> None:
    """A PR cut before a prune must neither fail to push nor resurrect the shard."""
    _, parsed = _render(invoke_cli, tmp_path, ci, _PIPELINES[ci])
    script = _pr_job_script(ci, parsed)
    dev, origin = ci_git["dev"], ci_git["origin"]
    _commit(dev, "seed", {"README.md": "detections\n", ".opentide/inflight/stale.json": "{}\n"})
    _git(dev, "push", "-q", "origin", "main")
    _git(dev, "checkout", "-q", "-b", "feature")
    _commit(dev, "add a rule", {_PR_OBJECT: "name: unreviewed\n"})
    _git(dev, "push", "-q", "origin", "feature")
    _git(dev, "checkout", "-q", "main")
    _commit(
        dev,
        "prune and another PR's shard",
        {".opentide/inflight/stale.json": None, ".opentide/inflight/other.json": "{}\n"},
    )
    _git(dev, "push", "-q", "origin", "main")

    _run_pr_job(ci, script, ci_git, "feature")

    tree = _main_tree(origin)
    assert {_NEW_SHARD, ".opentide/inflight/other.json", "README.md"} <= tree
    assert ".opentide/inflight/stale.json" not in tree
    assert _PR_OBJECT not in tree


@pytest.mark.parametrize("job_name", ["inflight_shards", "inflight_prune"])
def test_github_inflight_commits_when_shards_change(
    invoke_cli, tmp_path: Path, job_name: str
) -> None:
    """GitHub only worked through a ``set -e`` exemption; assert the explicit form."""
    _, parsed = _render(invoke_cli, tmp_path, "github", ".github/workflows/opentide.yml")
    steps = parsed["jobs"][job_name]["steps"]
    script = "\n".join(str(step["run"]) for step in steps if "run" in step)
    assert_commit_is_reachable(script, label=job_name)
