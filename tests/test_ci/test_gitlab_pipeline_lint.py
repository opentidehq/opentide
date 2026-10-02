"""Lint generated GitLab CI with glint and gitlab-ci-verify.

glint checks pipeline structure offline (needs, rules, a required script).
gitlab-ci-verify --no-lint-api runs ShellCheck on job scripts. Its GitLab
Pipeline Lint API needs a project token, so this test does not call it.

Install both with ``scripts/install-gitlab-ci-linters.sh`` and put that
directory on ``PATH``. CI sets ``OPENTIDE_GITLAB_CI_LINT=1`` so a missing
binary fails the job instead of skipping.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from itertools import product
from pathlib import Path

import pytest

from opentide.ci.models import CiRenderOptions
from opentide.ci.render import render_ci

pytestmark = pytest.mark.gitlab_ci_lint

_PLATFORM_SETS = (
    (),
    ("sentinel",),
    (
        "sentinel",
        "splunk",
        "defender_for_endpoint",
        "sentinel_one",
        "carbon_black_cloud",
        "crowdstrike",
        "harfanglab",
    ),
)


def _require_linters() -> tuple[str, str]:
    glint = shutil.which("glint")
    verify = shutil.which("gitlab-ci-verify")
    if glint and verify:
        return glint, verify
    missing = [
        name for name, found in (("glint", glint), ("gitlab-ci-verify", verify)) if not found
    ]
    message = (
        "Install glint and gitlab-ci-verify with scripts/install-gitlab-ci-linters.sh "
        f"(missing: {', '.join(missing)})"
    )
    if os.environ.get("OPENTIDE_GITLAB_CI_LINT") == "1":
        pytest.fail(message)
    pytest.skip(message)
    return "", ""


def _cases() -> list[CiRenderOptions]:
    cases: list[CiRenderOptions] = []
    for platforms, staging, inflight, sharing, docs in product(
        _PLATFORM_SETS, (True, False), (True, False), (True, False), (True, False)
    ):
        cases.append(
            CiRenderOptions(
                ci="gitlab",
                platforms=list(platforms),
                staging=staging,
                inflight=inflight,
                sharing=sharing,
                docs_enabled=docs,
            )
        )
    return cases


def test_generated_gitlab_pipelines_pass_glint_and_gitlab_ci_verify(tmp_path: Path) -> None:
    glint, verify = _require_linters()
    failures: list[str] = []
    for index, options in enumerate(_cases()):
        rendered = render_ci(options)
        assert list(rendered) == [".gitlab-ci.yml"]
        path = tmp_path / f"{index}.yml"
        path.write_text(rendered[".gitlab-ci.yml"], encoding="utf-8")
        commands = (
            (glint, ["check", "--offline", "--format", "text", str(path)]),
            (
                verify,
                [
                    "--no-lint-api",
                    "--severity",
                    "style",
                    "--format",
                    "text",
                    "--gitlab-ci-file",
                    str(path),
                ],
            ),
        )
        for binary, args in commands:
            result = subprocess.run(
                [binary, *args],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                detail = (result.stdout + result.stderr).strip()
                failures.append(
                    f"{Path(binary).name} exit {result.returncode} on {path.name}:\n{detail}"
                )
    assert not failures, "\n\n".join(failures)
