"""Lint the GitLab CI that ``opentide setup ci gitlab`` writes, with glint and gitlab-ci-verify.

glint checks pipeline structure offline (needs, rules, a required script).
gitlab-ci-verify --no-lint-api runs ShellCheck on job scripts. Its GitLab
Pipeline Lint API needs a project token, so this test does not call it.

The pipeline is the Rust command line's (UC-6.2, #841), rendered through the
console script on the tide corpus: with its platforms enabled, and with every
platform disabled.

Install both linters with ``scripts/install-gitlab-ci-linters.sh`` and put that
directory on ``PATH``. CI sets ``OPENTIDE_GITLAB_CI_LINT=1`` so a missing
binary fails the job instead of skipping.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from tests.corpus_support import materialise_corpus

pytestmark = pytest.mark.gitlab_ci_lint


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


def _without_platforms(repo: Path) -> None:
    folder = repo / ".opentide" / "configurations" / "platforms"
    for path in folder.glob("*.toml"):
        text = path.read_text(encoding="utf-8")
        path.write_text(
            re.sub(r"(?m)^enabled\s*=\s*true", "enabled = false", text), encoding="utf-8"
        )


def _render(repo: Path) -> Path:
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("OPENTIDE_") and name not in {"CI", "GITLAB_CI"}
    }
    env["NO_COLOR"] = "1"
    done = subprocess.run(
        [sys.executable, "-m", "opentide", "--repo", str(repo), "setup", "ci", "gitlab", "--yes"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    pipeline = repo / ".gitlab-ci.yml"
    assert pipeline.is_file(), done.stdout + done.stderr
    return pipeline


@pytest.mark.parametrize("platforms", ["enabled", "none"])
def test_generated_gitlab_pipelines_pass_glint_and_gitlab_ci_verify(
    tmp_path: Path, platforms: str
) -> None:
    glint, verify = _require_linters()
    repo = materialise_corpus(tmp_path / "corpus")
    if platforms == "none":
        _without_platforms(repo)
    path = _render(repo)
    failures: list[str] = []
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
        result = subprocess.run([binary, *args], check=False, capture_output=True, text=True)
        if result.returncode != 0:
            detail = (result.stdout + result.stderr).strip()
            failures.append(f"{Path(binary).name} exit {result.returncode}:\n{detail}")
    assert not failures, "\n\n".join(failures)
