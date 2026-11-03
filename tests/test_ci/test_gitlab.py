"""GitLab CI template generation tests."""

from __future__ import annotations

import yaml
from tests.gitlab_pipeline_support import GLOBAL_KEYS, PIPELINES, pipeline_jobs, unmet_needs

from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions


def test_render_gitlab_sets_repo_root_without_inflight() -> None:
    options = CiRenderOptions(ci="gitlab", inflight=False)
    content = render_gitlab(options)
    assert "variables:" in content
    assert "OPENTIDE_REPO_ROOT: $CI_PROJECT_DIR" in content
    preamble = content.split("\nstages:", 1)[0]
    assert "OPENTIDE_REPO_ROOT: $CI_PROJECT_DIR" in preamble
    assert "validate:" in content
    assert "generate:" in content


def test_render_gitlab_includes_stages() -> None:
    options = CiRenderOptions(ci="gitlab", platforms=["sentinel"])
    content = render_gitlab(options)
    assert "stages:" in content
    assert "validate" in content


def test_render_gitlab_has_no_promote_stage() -> None:
    options = CiRenderOptions(ci="gitlab", promotion=True)
    content = render_gitlab(options)
    assert "promote:" not in content
    assert "  - promote" not in content


def test_render_gitlab_inflight_job_when_enabled() -> None:
    options = CiRenderOptions(ci="gitlab", inflight=True)
    content = render_gitlab(options)
    assert "inflight_shards:" in content
    assert "inflight_prune:" in content
    assert "opentide generate inflight" in content
    assert "opentide generate inflight prune" in content
    # Removed in 0.17.0: the inflight diff is the pull request's, whatever the env.
    assert "DEPLOYMENT_PLAN" not in content


def test_render_gitlab_no_inflight_skips_inflight_job() -> None:
    options = CiRenderOptions(ci="gitlab", inflight=False)
    content = render_gitlab(options)
    assert "inflight_shards:" not in content


def test_generate_needs_every_query_validation_job() -> None:
    options = CiRenderOptions(
        ci="gitlab",
        platforms=[
            "crowdstrike",
            "sentinel",
            "harfanglab",
            "defender_for_endpoint",
            "splunk",
        ],
    )
    parsed = yaml.safe_load(render_gitlab(options))
    # Optional: a query job its rules leave out must not stop GitLab creating
    # the pipeline ("needs job ..., but it was not added to the pipeline").
    assert parsed["generate"]["needs"] == [
        "validate",
        {"job": "validate_query_sentinel", "optional": True},
        {"job": "validate_query_defender-for-endpoint", "optional": True},
        {"job": "validate_query_splunk", "optional": True},
    ]
    assert "validate_query_crowdstrike" not in parsed
    assert "validate_query_harfanglab" not in parsed
    assert parsed["deploy_production"]["needs"] == ["generate"]


def test_disabled_docs_omits_the_document_job() -> None:
    content = render_gitlab(CiRenderOptions(ci="gitlab", docs_enabled=False, sharing=True))
    parsed = yaml.safe_load(content)
    assert parsed["stages"] == ["validate", "generate", "deploy", "share"]
    assert "document" not in parsed
    assert "script:\n  needs:" not in content


def test_inflight_shell_quotes_the_default_branch_and_exits_on_cd_failure() -> None:
    content = render_gitlab(CiRenderOptions(ci="gitlab", inflight=True))
    assert 'git fetch origin "$CI_DEFAULT_BRANCH"' in content
    assert "git fetch origin $CI_DEFAULT_BRANCH\n" not in content
    assert 'cd "$shards_base" || exit' in content


def test_every_pipeline_gitlab_creates_can_start() -> None:
    """GitLab refuses a pipeline whose job needs a job that was not added.

    Through 0.16.1 the merge request pipeline held only ``deploy_staging`` and
    ``inflight_shards``: ``generate`` has no rules, so it defaulted to
    ``except: merge_requests``, and GitLab refused to start the pipeline.
    """
    options = CiRenderOptions(
        ci="gitlab",
        platforms=["sentinel", "splunk"],
        staging=True,
        inflight=True,
        sharing=True,
    )
    parsed = yaml.safe_load(render_gitlab(options))
    for pipeline, variables in PIPELINES.items():
        jobs = pipeline_jobs(parsed, variables)
        if jobs is None:
            continue
        assert not unmet_needs(parsed, jobs), pipeline


def test_rules_a_project_adds_to_any_job_never_stop_the_pipeline() -> None:
    """A query job skipped by a project's own ``rules:`` broke pipeline creation.

    ``generate`` needed every ``validate_query_*`` job without ``optional``.
    Here every job but ``validate`` and ``generate`` gets a rule that leaves
    it out, as a project might add, and every pipeline must still start.
    """
    options = CiRenderOptions(
        ci="gitlab", platforms=["sentinel", "splunk"], staging=True, inflight=True, sharing=True
    )
    parsed = yaml.safe_load(render_gitlab(options))
    for name, job in parsed.items():
        if name in GLOBAL_KEYS or name in ("validate", "generate"):
            continue
        # ``{}`` stands for ``- when: on_success``: a job without rules keeps running.
        original = job.get("rules") or [{}]
        job["rules"] = [{"if": '$SKIP_EVERYTHING == "1"', "when": "never"}, *original]
    for pipeline, variables in PIPELINES.items():
        jobs = pipeline_jobs(parsed, {**variables, "SKIP_EVERYTHING": "1"})
        if jobs is None:
            continue
        assert jobs == {"validate", "generate"}, pipeline
        assert not unmet_needs(parsed, jobs), pipeline


def test_merge_requests_validate_and_stage_and_branches_wait_for_one() -> None:
    options = CiRenderOptions(ci="gitlab", platforms=["sentinel"], staging=True, inflight=True)
    parsed = yaml.safe_load(render_gitlab(options))
    pipelines = {name: pipeline_jobs(parsed, env) for name, env in PIPELINES.items()}

    assert pipelines["merge request into the default branch"] == {
        "validate",
        "validate_query_sentinel",
        "generate",
        "deploy_staging",
        "inflight_shards",
    }
    # A merge request into another branch is validated but deploys nowhere.
    assert pipelines["merge request into another branch"] == {
        "validate",
        "validate_query_sentinel",
        "generate",
    }
    assert pipelines["push to the default branch"] == {
        "validate",
        "validate_query_sentinel",
        "generate",
        "deploy_production",
        "inflight_prune",
        "document",
    }
    # No branch pipeline beside the merge request pipeline: one pipeline per push.
    assert pipelines["push to a feature branch"] is None


def test_deploy_jobs_record_deployments_in_an_environment() -> None:
    """Without ``environment:`` GitLab kept no deployment history and no DORA metrics."""
    parsed = yaml.safe_load(render_gitlab(CiRenderOptions(ci="gitlab", platforms=["sentinel"])))
    assert parsed["deploy_production"]["environment"] == {
        "name": "production",
        "deployment_tier": "production",
    }
    staging = parsed["deploy_staging"]["environment"]
    # One per merge request: GitLab fails an older pipeline's deployment job
    # once a newer one deployed to the same environment.
    assert staging["name"] == "staging/mr-$CI_MERGE_REQUEST_IID"
    assert staging["deployment_tier"] == "staging"
    assert staging["auto_stop_in"] == "1 week"
    deploying = {
        name
        for name, job in parsed.items()
        if isinstance(job, dict)
        and any("opentide deploy --strategy" in line for line in job.get("script", []))
    }
    assert deploying == {"deploy_staging", "deploy_production"}
    with_environment = [
        name for name, job in parsed.items() if isinstance(job, dict) and "environment" in job
    ]
    assert sorted(with_environment) == sorted(deploying)
