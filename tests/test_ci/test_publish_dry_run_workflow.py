"""Contract for ``publish-dry-run.yml``: it rehearses every publish and can make none.

The workflow runs on pull requests, including ones that change it, so the
property that matters is structural: no job can mint the OIDC token that
trusted publishing on crates.io, npm and PyPI exchanges for an upload token, no
secret is read, and every publish command is a dry run. It also has to stay a
faithful rehearsal: the wheel and sdist built the way ``publish-pypi.yml``
builds them, npm new enough for trusted publishing, and every placeholder in
``publishing/placeholders/`` covered (UC-0.1, #799).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-dry-run.yml"
PUBLISH_PYPI = ROOT / ".github" / "workflows" / "publish-pypi.yml"
PLACEHOLDERS = ROOT / "publishing" / "placeholders"
#: What trusted publishing on npm needs (docs.npmjs.com/trusted-publishers).
NPM_FLOOR = (11, 5, 1)
#: Commands that publish, log in, change who may publish, or change what a
#: registry or a release already holds.
FORBIDDEN = (
    "twine upload",
    "gh-action-pypi-publish",
    "uv publish",
    "maturin publish",
    "maturin upload",
    "hatch publish",
    "poetry publish",
    "flit publish",
    "crates-io-auth-action",
    "cargo login",
    "cargo owner",
    "cargo yank",
    "npm login",
    "npm owner",
    "npm trust",
    "npm stage",
    "npm dist-tag",
    "npm access",
    "npm unpublish",
    "npm deprecate",
    "pnpm publish",
    "yarn publish",
    "yarn npm publish",
    "gh release",
    "action-gh-release",
)
#: The workflow's whole trigger set: no `pull_request_target` or `workflow_run`,
#: which run with the base repository's token and secrets.
TRIGGERS = {"pull_request", "push", "workflow_dispatch"}
#: What a release builds from, besides the placeholders and this workflow.
#: `crates/**`, `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml` arrive
#: with UC-0.2, which compiles the engine from a root Cargo workspace.
PUBLISHED_FROM = {
    "publishing/**",
    ".github/workflows/publish-dry-run.yml",
    "pyproject.toml",
    "hatch_build.py",
    "analysis/**",
    "crates/**",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "scripts/build/release.py",
}
#: One publish command: from `cargo publish` or `npm publish` to the end of
#: that shell command (`;`, `&&`, `||`, a pipe, a closing subshell or the line).
_PUBLISH = re.compile(r"\b(?:cargo|npm) publish\b[^;&|)\n]*")
#: `--dry-run` as a flag of its own: not `--dry-run=false`, not `--no-dry-run`.
_DRY_RUN = re.compile(r"(?<!\S)--dry-run(?!\S)")
_NOT_DRY_RUN = re.compile(r"--dry-run=|--no-dry-run\b")
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", flags=re.DOTALL)
_SECRETS = re.compile(r"\bsecrets\b")
_PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _load(path: Path) -> dict[Any, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def workflow() -> dict[Any, Any]:
    return _load(WORKFLOW)


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML (YAML 1.1) reads the bare `on` key as boolean True.
    return workflow.get("on", workflow.get(True))


def _steps(workflow: dict[Any, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for name, job in workflow["jobs"].items():
        # A job without steps fails test_every_job_runs_its_own_steps instead.
        for step in job.get("steps", []):
            yield name, step


def _runs(workflow: dict[Any, Any], job: str | None = None) -> list[str]:
    return [
        step["run"]
        for name, step in _steps(workflow)
        if "run" in step and (job is None or name == job)
    ]


def _strings(node: Any) -> Iterator[str]:
    """Every key and scalar in the parsed workflow: comments are not in it."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)
    elif node is not None:
        yield str(node)


def _expressions(workflow: dict[Any, Any]) -> Iterator[str]:
    """Every expression GitHub evaluates: each ``${{ }}``, and each ``if:``, which
    is an expression with or without the braces."""
    for text in _strings(workflow):
        yield from _EXPRESSION.findall(text)
    for job in workflow["jobs"].values():
        conditions = [job.get("if"), *(step.get("if") for step in job.get("steps", []))]
        yield from (str(condition) for condition in conditions if condition is not None)


def test_token_is_read_only_everywhere(workflow: dict[Any, Any]) -> None:
    assert workflow["permissions"] == {"contents": "read"}
    widened = [name for name, job in workflow["jobs"].items() if "permissions" in job]
    assert widened == []


def test_no_oidc_token_no_secret_no_environment(workflow: dict[Any, Any]) -> None:
    # id-token: write is what every registry's trusted publishing needs; an
    # environment is where a publisher's protection rules and secrets live.
    text = list(_strings(workflow))
    assert not [value for value in text if "id-token" in value]
    assert not [value for value in text if "secrets." in value or "secrets[" in value]
    assert not [name for name, job in workflow["jobs"].items() if "environment" in job]


def test_no_expression_reads_the_secrets_context(workflow: dict[Any, Any]) -> None:
    # `toJSON(secrets)` reads every secret without the `secrets.` the test above
    # looks for, and `if: secrets.X` needs no braces.
    assert [
        expression for expression in _expressions(workflow) if _SECRETS.search(expression)
    ] == []


def test_every_job_runs_its_own_steps(workflow: dict[Any, Any]) -> None:
    # A job that calls a reusable workflow (`uses:`) runs steps this test cannot
    # see, and `secrets: inherit` hands it every secret.
    jobs = workflow["jobs"]
    assert [name for name, job in jobs.items() if "uses" in job or "secrets" in job] == []
    assert [name for name, job in jobs.items() if not job.get("steps")] == []


def test_every_publish_command_is_a_dry_run(workflow: dict[Any, Any]) -> None:
    # Each command, not each line: `npm publish --dry-run && npm publish` is one
    # line and two publishes. A continued line is joined to the next first.
    publishes = [
        command.strip()
        for run in _runs(workflow)
        for command in _PUBLISH.findall(run.replace("\\\n", " "))
    ]
    assert publishes, "the workflow rehearses no publish"
    assert [
        command
        for command in publishes
        if not _DRY_RUN.search(command) or _NOT_DRY_RUN.search(command)
    ] == []


def test_nothing_logs_in_uploads_or_changes_owners(workflow: dict[Any, Any]) -> None:
    text = "\n".join(_strings(workflow))
    assert [command for command in FORBIDDEN if command in text] == []


def test_actions_are_pinned_by_commit(workflow: dict[Any, Any]) -> None:
    uses = [step["uses"] for _, step in _steps(workflow) if "uses" in step]
    assert uses
    assert [action for action in uses if not _PINNED.match(action)] == []


def test_no_expression_is_interpolated_into_a_script(workflow: dict[Any, Any]) -> None:
    # Values reach the scripts through env:, never as text spliced into them.
    assert [run for run in _runs(workflow) if "${{" in run] == []


def test_runs_whenever_what_is_published_changes(workflow: dict[Any, Any]) -> None:
    triggers = _triggers(workflow)
    paths = triggers["pull_request"]["paths"]
    assert set(paths) >= PUBLISHED_FROM, sorted(PUBLISHED_FROM - set(paths))
    assert triggers["push"] == {"branches": ["development"], "paths": paths}
    assert "workflow_dispatch" in triggers


def test_runs_on_no_trigger_that_carries_the_base_repository_secrets(
    workflow: dict[Any, Any],
) -> None:
    assert set(_triggers(workflow)) == TRIGGERS


def test_crate_job_rehearses_the_placeholder(workflow: dict[Any, Any]) -> None:
    manifest = workflow["jobs"]["crate"]["env"]["MANIFEST"]
    assert (ROOT / manifest).is_file()
    assert Path(manifest).parent == (PLACEHOLDERS / "crates" / "opentide").relative_to(ROOT)
    runs = "\n".join(_runs(workflow, "crate"))
    assert 'cargo publish --manifest-path "${MANIFEST}" --locked --dry-run' in runs


def test_npm_job_rehearses_every_npm_placeholder(workflow: dict[Any, Any]) -> None:
    runs = "\n".join(_runs(workflow, "npm"))
    directories = {path.relative_to(ROOT).as_posix() for path in PLACEHOLDERS.glob("npm/*")}
    assert directories
    # One name is a prefix of the other: compare the loop's words, not substrings.
    (loop,) = re.findall(r"^\s*for dir in ([^;]+); do$", runs, flags=re.MULTILINE)
    assert set(loop.split()) == directories


def test_npm_is_new_enough_for_trusted_publishing(workflow: dict[Any, Any]) -> None:
    runs = "\n".join(_runs(workflow, "npm"))
    pins = re.findall(r"npm install --global npm@(\d+)\.(\d+)\.(\d+)\b", runs)
    assert len(pins) == 1, pins
    assert tuple(int(part) for part in pins[0]) >= NPM_FLOOR


def test_pypi_job_builds_as_the_release_does(workflow: dict[Any, Any]) -> None:
    release = _load(PUBLISH_PYPI)
    release_runs = "\n".join(_runs(release))
    runs = "\n".join(_runs(workflow, "pypi"))
    (cibuildwheel,) = set(re.findall(r"cibuildwheel==[\w.]+", release_runs))
    assert f"python -m pip install {cibuildwheel}" in runs
    assert "python -m cibuildwheel --output-dir dist" in runs
    assert "uv build --sdist" in runs
    assert "twine check dist/*" in runs
    # Same interpreter as the release's wheel builds, and the version the
    # release guard reads, passed to both builds.
    python = {
        step["with"]["python-version"]
        for name, step in _steps(release)
        if name == "wheels" and str(step.get("uses", "")).startswith("actions/setup-python@")
    }
    steps = workflow["jobs"]["pypi"]["steps"]
    assert {
        step["with"]["python-version"]
        for step in steps
        if str(step.get("uses", "")).startswith("actions/setup-python@")
    } == python
    builds = [
        step
        for step in steps
        if "cibuildwheel" in step.get("run", "") or step.get("run") == "uv build --sdist"
    ]
    assert len(builds) == 2
    for step in builds:
        assert (
            step["env"]["SETUPTOOLS_SCM_PRETEND_VERSION"] == "${{ steps.version.outputs.version }}"
        )
    assert "scripts/build/release.py version" in runs


def test_pypi_job_refuses_what_the_release_refuses(workflow: dict[Any, Any]) -> None:
    # The publish job rejects a dev or local version before it compares the
    # version with the guard's; the rehearsal keeps the same check.
    check = 'any("dev" in v or "+" in v for v in versions)'
    assert check in "\n".join(_runs(_load(PUBLISH_PYPI), "publish"))
    assert check in "\n".join(_runs(workflow, "pypi"))
