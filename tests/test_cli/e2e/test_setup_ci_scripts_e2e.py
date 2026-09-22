"""CLI E2E: the job *scripts* inside generated pipelines have to be runnable.

``test_setup_ci_e2e.py`` proves the rendered pipelines are valid YAML. That is
what let #244 through: ``${{CI_JOB_TOKEN}}`` and an ``&&`` chain that skips
``git commit`` are both perfectly well-formed YAML. These tests read the job
scripts and assert provider-correct variable syntax and commit control flow.
"""

from __future__ import annotations

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


def _gitlab_scripts(parsed: dict[str, Any]) -> dict[str, str]:
    """Job name to its flattened ``script`` body."""
    scripts: dict[str, str] = {}
    for name, job in parsed.items():
        if not isinstance(job, dict) or "script" not in job:
            continue
        script = job["script"]
        lines = script if isinstance(script, list) else [script]
        scripts[name] = "\n".join(str(line) for line in lines)
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
    guard_end = script.index("fi")
    assert script.index("git commit") > guard_end, (
        f"{label}: commit runs inside the emptiness guard\n{script}"
    )
    for line in script.splitlines():
        if "exit 0" in line:
            assert "&&" not in line, f"{label}: `exit 0` in an && chain\n{line}"


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
    """Dropping the ``&&`` join must not drop the fail-fast it provided."""
    _, parsed = _render(invoke_cli, tmp_path, "azure", "azure-pipelines.yml")
    for name, job in _azure_jobs(parsed).items():
        for step in job["steps"]:
            script = str(step.get("script", ""))
            if not script.startswith("set -e"):
                continue
            assert script.splitlines()[0] == "set -e", f"{name}: {script}"


def test_github_keeps_its_own_expression_syntax(invoke_cli, tmp_path: Path) -> None:
    """The negative assertions above must not be applied to the GitHub workflow."""
    rendered, parsed = _render(invoke_cli, tmp_path, "github", ".github/workflows/opentide.yml")
    assert GITHUB_EXPRESSION in rendered
    assert parsed["env"]["OPENTIDE_REPO_ROOT"] == "${{ github.workspace }}"


@pytest.mark.parametrize("job_name", ["inflight_shards", "inflight_prune"])
def test_github_inflight_commits_when_shards_change(
    invoke_cli, tmp_path: Path, job_name: str
) -> None:
    """GitHub only worked through a ``set -e`` exemption; assert the explicit form."""
    _, parsed = _render(invoke_cli, tmp_path, "github", ".github/workflows/opentide.yml")
    steps = parsed["jobs"][job_name]["steps"]
    script = "\n".join(str(step["run"]) for step in steps if "run" in step)
    assert_commit_is_reachable(script, label=job_name)
