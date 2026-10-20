"""GitLab CI template generation tests."""

from __future__ import annotations

import yaml

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
    assert parsed["generate"]["needs"] == [
        "validate",
        "validate_query_sentinel",
        "validate_query_defender-for-endpoint",
        "validate_query_splunk",
    ]
    assert "validate_query_crowdstrike" not in parsed
    assert "validate_query_harfanglab" not in parsed
    assert parsed["deploy_production"]["needs"] == ["generate"]


def test_disabled_docs_omits_the_document_job() -> None:
    content = render_gitlab(CiRenderOptions(ci="gitlab", docs_enabled=False, sharing=True))
    parsed = yaml.safe_load(content)
    assert parsed["stages"] == ["validate", "generate", "share", "deploy"]
    assert "document" not in parsed
    assert "script:\n  needs:" not in content


def test_inflight_shell_quotes_the_default_branch_and_exits_on_cd_failure() -> None:
    content = render_gitlab(CiRenderOptions(ci="gitlab", inflight=True))
    assert 'git fetch origin "$CI_DEFAULT_BRANCH"' in content
    assert "git fetch origin $CI_DEFAULT_BRANCH\n" not in content
    assert 'cd "$shards_base" || exit' in content


#: Top-level keys that are not jobs.
_GLOBAL_KEYS = frozenset({"workflow", "variables", "stages", "default", "include"})

#: The pipelines a project sees. ``CI_COMMIT_BRANCH`` is unset in merge request
#: pipelines, and GitLab compares an unset variable as null.
_PIPELINES: dict[str, dict[str, str]] = {
    "merge request into the default branch": {
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        "CI_DEFAULT_BRANCH": "main",
    },
    "merge request into another branch": {
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "release",
        "CI_DEFAULT_BRANCH": "main",
    },
    "push to the default branch": {
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_BRANCH": "main",
        "CI_DEFAULT_BRANCH": "main",
    },
    "push to a feature branch": {
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_BRANCH": "feature",
        "CI_DEFAULT_BRANCH": "main",
    },
}


def _operand(token: str, variables: dict[str, str]) -> str | None:
    token = token.strip()
    if token.startswith("$"):
        return variables.get(token[1:])
    return token.strip('"')


def _matches(expression: str, variables: dict[str, str]) -> bool:
    """Evaluate the ``&&``-joined ``==`` / ``!=`` comparisons the generator writes."""
    for clause in expression.split("&&"):
        operator = "!=" if "!=" in clause else "=="
        left, right = clause.split(operator)
        equal = _operand(left, variables) == _operand(right, variables)
        if equal != (operator == "=="):
            return False
    return True


def _pipeline_jobs(parsed: dict[str, object], variables: dict[str, str]) -> set[str] | None:
    """The jobs GitLab adds for *variables*, or ``None`` when no pipeline is created.

    A job with ``rules`` is added when one ``if`` matches. A job without them
    defaults to ``except: merge_requests``, unless ``workflow:rules`` is set,
    which drops that default (GitLab docs: "Use the workflow: rules keyword to
    configure all jobs in a pipeline to run in merge request pipelines").
    """
    workflow = parsed.get("workflow")
    if isinstance(workflow, dict) and not any(
        _matches(rule["if"], variables) for rule in workflow["rules"]
    ):
        return None
    merge_request = variables.get("CI_PIPELINE_SOURCE") == "merge_request_event"
    jobs: set[str] = set()
    for name, job in parsed.items():
        if name in _GLOBAL_KEYS or not isinstance(job, dict):
            continue
        rules = job.get("rules")
        if rules:
            if any(_matches(rule["if"], variables) for rule in rules):
                jobs.add(name)
        elif workflow is not None or not merge_request:
            jobs.add(name)
    return jobs


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
    for pipeline, variables in _PIPELINES.items():
        jobs = _pipeline_jobs(parsed, variables)
        if jobs is None:
            continue
        for job in jobs:
            missing = set(parsed[job].get("needs") or ()) - jobs
            assert not missing, f"{pipeline}: {job} needs {sorted(missing)}, not added"


def test_merge_requests_validate_and_stage_and_branches_wait_for_one() -> None:
    options = CiRenderOptions(ci="gitlab", platforms=["sentinel"], staging=True, inflight=True)
    parsed = yaml.safe_load(render_gitlab(options))
    pipelines = {name: _pipeline_jobs(parsed, env) for name, env in _PIPELINES.items()}

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
