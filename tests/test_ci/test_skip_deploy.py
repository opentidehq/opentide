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
    azure_not_skipped,
    azure_pull_request_skip_guard,
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
    assert azure_not_skipped() in jobs["deploy_production"]["condition"]
    assert azure_not_skipped() in stages["Share"]["condition"]
    for name in ("validate_query_sentinel", "validate_query_splunk"):
        assert azure_not_skipped() in jobs[name]["condition"]
    # Pull request builds read the source commit's message in the job.
    for name in ("deploy_staging", "validate_query_sentinel"):
        script = jobs[name]["steps"][-1]["script"]
        assert script.splitlines()[1] == azure_pull_request_skip_guard(), name
    assert "condition" not in jobs["validate"]


_GIT = shutil.which("git")
_BASH = shutil.which("bash")


@pytest.mark.skipif(_GIT is None or _BASH is None, reason="needs git and bash")
@pytest.mark.parametrize(
    ("message", "source", "skipped"),
    [
        ("style: reformat [skip deploy]", True, True),
        ("feat: add a rule", True, False),
        ("style: reformat [skip deploy]", False, False),
    ],
    ids=["marker", "no-marker", "not-a-pull-request"],
)
def test_the_azure_pull_request_guard_reads_the_source_commit(
    tmp_path: Path, message: str, source: bool, skipped: bool
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
    if source:
        env["SYSTEM_PULLREQUEST_SOURCECOMMITID"] = head
    script = "\n".join(["set -e", azure_pull_request_skip_guard(), "echo deployed"])
    done = subprocess.run(
        [_BASH, "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 0, done.stderr
    assert ("deployed" in done.stdout) is not skipped
    assert (SKIP_DEPLOY_NOTE in done.stdout) is skipped
