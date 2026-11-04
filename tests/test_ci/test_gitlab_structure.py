"""Structural checks on every GitLab pipeline the generator can write.

Each pipeline is parsed back and checked for what GitLab enforces when it
creates or runs a pipeline, over every combination of generator options.
"""

from __future__ import annotations

from itertools import product
from typing import Any

import pytest
import yaml
from tests.gitlab_pipeline_support import (
    GLOBAL_KEYS,
    PIPELINES,
    needs_of,
    pipeline_jobs,
    unmet_needs,
)

from opentide.ci.gitlab import pipeline_document, render_gitlab
from opentide.ci.models import CiRenderOptions
from opentide.ci.text import dump_pipeline

_PLATFORM_SETS = (
    (),
    ("sentinel",),
    ("sentinel", "splunk", "defender_for_endpoint", "crowdstrike", "harfanglab", "elastic"),
)


def _cases() -> list[CiRenderOptions]:
    return [
        CiRenderOptions(
            ci="gitlab",
            platforms=list(platforms),
            staging=staging,
            inflight=inflight,
            sharing=sharing,
            docs_enabled=docs,
        )
        for platforms, staging, inflight, sharing, docs in product(
            _PLATFORM_SETS, (True, False), (True, False), (True, False), (True, False)
        )
    ]


def _case_id(options: CiRenderOptions) -> str:
    flags = [
        name
        for name in ("staging", "inflight", "sharing", "docs_enabled")
        if getattr(options, name)
    ]
    return "-".join([str(len(options.platforms)), *flags])


CASES = _cases()


def jobs_of(pipeline: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        name: body
        for name, body in pipeline.items()
        if name not in GLOBAL_KEYS and isinstance(body, dict)
    }


@pytest.mark.parametrize("options", CASES, ids=_case_id)
def test_every_pipeline_gitlab_creates_can_start(options: CiRenderOptions) -> None:
    parsed = yaml.safe_load(render_gitlab(options))
    for pipeline, variables in PIPELINES.items():
        jobs = pipeline_jobs(parsed, variables)
        if jobs is not None:
            assert not unmet_needs(parsed, jobs), pipeline


@pytest.mark.parametrize("options", CASES, ids=_case_id)
def test_pipeline_text_parses_to_the_document_it_was_built_from(options: CiRenderOptions) -> None:
    assert yaml.safe_load(render_gitlab(options)) == pipeline_document(options)


@pytest.mark.parametrize("options", CASES, ids=_case_id)
def test_every_job_is_well_formed(options: CiRenderOptions) -> None:
    pipeline = yaml.safe_load(render_gitlab(options))
    stages = pipeline["stages"]
    jobs = jobs_of(pipeline)
    for name, job in jobs.items():
        assert job["stage"] in stages, f"{name}: stage {job['stage']} is not declared"
        for key in ("before_script", "script", "after_script"):
            lines = job.get(key, [])
            assert isinstance(lines, list), f"{name}.{key} is not a list"
            assert all(isinstance(line, str) and line for line in lines), f"{name}.{key}"
        assert job["script"], f"{name} has an empty script (GL003)"
        for need, _optional in needs_of(job):
            assert need in jobs, f"{name} needs {need}, which the pipeline does not define"
            assert stages.index(jobs[need]["stage"]) <= stages.index(job["stage"]), (
                f"{name} needs {need} from a later stage"
            )


@pytest.mark.parametrize("options", CASES, ids=_case_id)
def test_a_job_that_rules_can_leave_out_is_an_optional_need(options: CiRenderOptions) -> None:
    """GitLab refuses the whole pipeline when a job needs one its rules left out.

    ``generate`` needed every ``validate_query_*`` job without ``optional``,
    so any ``rules:`` on a query job broke pipeline creation with "needs job
    ..., but it was not added to the pipeline". A job that has no ``rules``
    is in every pipeline ``workflow:rules`` allows; any other need is optional.
    """
    jobs = jobs_of(yaml.safe_load(render_gitlab(options)))
    for name, job in jobs.items():
        for need, optional in needs_of(job):
            if "rules" in jobs[need]:
                assert optional, f"{name} needs {need}, which has rules, without optional: true"


@pytest.mark.parametrize("options", CASES, ids=_case_id)
def test_every_report_is_one_file(options: CiRenderOptions) -> None:
    """GitLab Runner 18.9 uploads a ``raw`` report as one file and fails the job on more.

    ``failed to copy content to form: only one file can be sent as raw``: the
    validate job declared a Code Quality file per gate command and failed
    after both commands passed.
    """
    jobs = jobs_of(yaml.safe_load(render_gitlab(options)))
    declared = 0
    for name, job in jobs.items():
        reports = job.get("artifacts", {}).get("reports", {})
        for kind, files in reports.items():
            declared += 1
            assert isinstance(files, str) or len(files) == 1, f"{name}: {kind} lists {files}"
            assert "*" not in str(files), f"{name}: {kind} is a glob"
    assert declared, "no report declared: the check checks nothing"


def test_the_validate_job_merges_every_report_it_writes() -> None:
    from opentide.ci.stages import CODEQUALITY_REPORT, GATE_COMMANDS, report_path

    validate = yaml.safe_load(render_gitlab(CASES[0]))["validate"]
    (merge,) = validate["after_script"]
    assert merge.startswith("python -m opentide.ci.codequality ")
    assert f"--output {CODEQUALITY_REPORT}" in merge
    for command in GATE_COMMANDS:
        written = report_path(command, "codequality")
        assert any(written in line for line in validate["script"])
        assert written in merge
    assert validate["artifacts"]["reports"]["codequality"] == CODEQUALITY_REPORT


def test_dump_pipeline_quotes_what_yaml_would_read_differently() -> None:
    document = {
        "job": {
            "variables": {"A": "yes", "B": "1.0", "C": "0", "D": "null"},
            "script": ['git commit -m "ci: record"', "echo a # b", "- not a list", "line\nline"],
        }
    }
    assert yaml.safe_load(dump_pipeline(document)) == document


def test_dump_pipeline_separates_top_level_keys() -> None:
    text = dump_pipeline({"a": {"script": ["one\ntwo\n"]}, "b": {"script": ["x"]}})
    assert text == "a:\n  script:\n    - |\n      one\n      two\n\nb:\n  script:\n    - x\n"


def test_dump_pipeline_checks_the_text_it_writes() -> None:
    """A `|+` value keeps trailing blank lines, so the blank line between keys joined it."""
    document = {"job": {"script": ["end\n\n"]}, "k2": {"x": 1}}
    try:
        text = dump_pipeline(document)
    except ValueError:
        return
    assert yaml.safe_load(text) == document
