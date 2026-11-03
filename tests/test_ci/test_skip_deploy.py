"""``[skip deploy]`` and the ``skip-deploy`` label keep a catalogue-wide change from deploying.

A migration, bulk rename or reformat changes every rule file. Its merge
request staging-deployed every PREVIEW rule and live-checked every query, and
its merge promoted every PREVIEW rule and redeployed the catalogue, with
nothing to stop it.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from tests.gitlab_pipeline_support import PIPELINES, pipeline_jobs, unmet_needs

from opentide.ci.azure import render_azure
from opentide.ci.gates import (
    SKIP_DEPLOY_NOTE,
    azure_skip_guard,
    github_not_skipped,
)
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions

_MR = PIPELINES["merge request into the default branch"]
_PUSH = PIPELINES["push to the default branch"]


def _options(ci: str) -> CiRenderOptions:
    return CiRenderOptions(
        ci=ci, platforms=["sentinel", "splunk"], staging=True, inflight=True, sharing=True
    )


def _gitlab() -> dict:
    return yaml.safe_load(render_gitlab(_options("gitlab")))


# --- GitLab -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "skip",
    [
        {"CI_MERGE_REQUEST_LABELS": "detection,skip-deploy"},
        {"CI_MERGE_REQUEST_LABELS": "skip-deploy"},
        {"CI_MERGE_REQUEST_TITLE": "Reformat every rule [skip deploy]"},
        {"CI_COMMIT_MESSAGE": "style: reformat the catalogue\n\n[skip deploy]"},
    ],
    ids=["label", "only-label", "title", "commit"],
)
def test_a_gitlab_merge_request_can_skip_staging_and_live_checks(skip: dict[str, str]) -> None:
    parsed = _gitlab()
    jobs = pipeline_jobs(parsed, {**_MR, **skip})
    assert jobs == {"validate", "generate", "inflight_shards"}
    assert not unmet_needs(parsed, jobs)


def test_a_gitlab_merge_skips_production_share_and_live_checks() -> None:
    parsed = _gitlab()
    message = "Merge branch 'reformat' into 'main'\n\nReformat every rule [skip deploy]"
    jobs = pipeline_jobs(parsed, {**_PUSH, "CI_COMMIT_MESSAGE": message})
    assert jobs == {"validate", "generate", "inflight_prune", "document"}
    assert not unmet_needs(parsed, jobs)


@pytest.mark.parametrize(
    "near_miss",
    [
        {"CI_MERGE_REQUEST_LABELS": "no-skip-deploy,skip-deployment"},
        {"CI_MERGE_REQUEST_TITLE": "skip deploy"},
        {"CI_COMMIT_MESSAGE": "[skip ci-deploy]"},
    ],
    ids=["other-labels", "no-brackets", "other-marker"],
)
def test_only_the_exact_label_or_marker_skips(near_miss: dict[str, str]) -> None:
    parsed = _gitlab()
    jobs = pipeline_jobs(parsed, {**_MR, **near_miss})
    assert jobs is not None
    assert {"deploy_staging", "validate_query_sentinel", "validate_query_splunk"} <= jobs


def test_without_a_marker_everything_still_runs() -> None:
    parsed = _gitlab()
    merge_request = pipeline_jobs(parsed, _MR)
    assert merge_request is not None
    assert {"deploy_staging", "validate_query_sentinel"} <= merge_request
    push = pipeline_jobs(parsed, _PUSH)
    assert push is not None
    assert {"deploy_production", "share", "validate_query_splunk"} <= push


# --- GitHub -----------------------------------------------------------------------------


def test_github_jobs_that_deploy_share_or_live_check_honour_the_marker() -> None:
    jobs = yaml.safe_load(render_github(_options("github")))["jobs"]
    for name in ("deploy_staging", "deploy_production", "share"):
        assert github_not_skipped() in jobs[name]["if"], name
    query = next(
        step
        for step in jobs["validate"]["steps"]
        if step.get("name") == "Validate queries on reviewed tenants"
    )
    assert query["if"] == f"${{{{ {github_not_skipped()} }}}}"
    # Object validation, docs and the inflight shards still run.
    for name in ("validate", "generate", "document", "inflight_shards", "inflight_prune"):
        assert "skip deploy" not in str(jobs[name].get("if", "")), name
    assert "'[skip deploy]'" in github_not_skipped()
    assert "pull_request.labels.*.name, 'skip-deploy'" in github_not_skipped()


# --- Azure ------------------------------------------------------------------------------


def test_azure_jobs_that_deploy_share_or_live_check_honour_the_marker() -> None:
    parsed = yaml.safe_load(render_azure(_options("azure")))
    stages = {stage["stage"]: stage for stage in parsed["stages"]}
    jobs = {job["job"]: job for stage in parsed["stages"] for job in stage["jobs"]}
    # Build.SourceVersionMessage is empty in a job or stage condition: no
    # condition may read it, the job's first step checks the commit instead.
    assert "SourceVersionMessage" not in render_azure(_options("azure"))
    assert "Share" in stages
    for name in (
        "deploy_staging",
        "deploy_production",
        "share",
        "validate_query_sentinel",
        "validate_query_splunk",
    ):
        script = next(
            step["script"]
            for step in jobs[name]["steps"]
            if step.get("script", "").startswith("set -e")
        )
        # First, before any deploy, share, query or DEPLOY_STARTED.
        assert script.splitlines()[1] == azure_skip_guard(), name
    assert azure_skip_guard() not in str(jobs["validate"])


_GIT = shutil.which("git")
_BASH = shutil.which("bash")


@pytest.mark.skipif(_GIT is None or _BASH is None, reason="needs git and bash")
@pytest.mark.parametrize(
    ("message", "variable", "skipped"),
    [
        ("style: reformat [skip deploy]", "SYSTEM_PULLREQUEST_SOURCECOMMITID", True),
        ("feat: add a rule", "SYSTEM_PULLREQUEST_SOURCECOMMITID", False),
        ("Merged PR 12: reformat [skip deploy]", "BUILD_SOURCEVERSION", True),
        ("Merged PR 13: add a rule", "BUILD_SOURCEVERSION", False),
        ("style: reformat [skip deploy]", None, False),
    ],
    ids=["pull-request-marker", "pull-request", "push-marker", "push", "no-commit"],
)
def test_the_azure_guard_reads_the_built_commit(
    tmp_path: Path, message: str, variable: str | None, skipped: bool
) -> None:
    assert _GIT and _BASH
    for args in (
        ("init", "-q"),
        ("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q"),
    ):
        extra = ["--allow-empty", "-m", message] if "commit" in args else []
        subprocess.run([_GIT, *args, *extra], cwd=tmp_path, check=True, capture_output=True)
    head = subprocess.run(
        [_GIT, "rev-parse", "HEAD"], cwd=tmp_path, capture_output=True, text=True, check=True
    ).stdout.strip()
    env = {"PATH": str(Path(_GIT).parent), "HOME": str(tmp_path)}
    if variable is not None:
        env[variable] = head
    script = "\n".join(["set -e", azure_skip_guard(), "echo deployed"])
    done = subprocess.run(
        [_BASH, "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 0, done.stderr
    assert ("deployed" in done.stdout) is not skipped
    assert (SKIP_DEPLOY_NOTE in done.stdout) is skipped
