"""Contract for ``publish-dry-run.yml``: it rehearses every publish and can make none.

The workflow runs on pull requests, including ones that change it, so the
property that matters is structural: no job can mint the OIDC token that
trusted publishing on crates.io, npm and PyPI exchanges for an upload token, no
secret is read, and every publish command is a dry run. It also has to stay a
faithful rehearsal: the wheel and sdist built the way ``publish.yml``
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
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"
#: The release's wheel build (publish.yml calls it).
PACKAGES = ROOT / ".github" / "workflows" / "build-packages.yml"
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
TRIGGERS = {"pull_request", "push", "schedule", "workflow_dispatch"}
#: A pull request runs the jobs only in ci.yml's full set (the `full-ci` label).
FULL_SET = (
    "github.event_name != 'pull_request' || "
    "contains(github.event.pull_request.labels.*.name, 'full-ci')"
)
#: What a release builds from, besides the placeholders and this workflow.
#: `crates/**`, `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml` arrive
#: with UC-0.2, which compiles the engine from a root Cargo workspace.
PUBLISHED_FROM = {
    "publishing/**",
    ".github/workflows/publish-dry-run.yml",
    "pyproject.toml",
    "hatch_build.py",
    "bindings/python/**",
    "crates/**",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "scripts/build/release.py",
}
#: Where a shell command ends: `;`, `&&`, `||`, `&`, a pipe, a subshell or a
#: command substitution, a backtick, or the end of the line.
_COMMAND_END = re.compile(r"&&|\|\||[;&|()`\n]")
#: The words each tool runs as a publish. npm runs every prefix of `publish`
#: from `pu` on (npm 11.21.1, `deref` in lib/utils/cmd-list.js), and takes
#: options before the command as well as after it; cargo has no abbreviation.
_PUBLISH_WORDS = {
    "npm": frozenset("publish"[:end] for end in range(2, len("publish") + 1)),
    "cargo": frozenset({"publish"}),
}
#: Any spelling of npm's `dry-run` option: one or two dashes, an abbreviation
#: (`--dry`), `--no-` before it, a value after `=` (nopt, which parses npm's
#: options). A dry run has the plain `--dry-run` and no other.
_DRY_RUN_OPTION = re.compile(r"^-+(?:no-)*dr", flags=re.IGNORECASE)
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


def _unquote(word: str) -> str:
    return word.replace('"', "").replace("'", "")


def _publishes(script: str) -> list[list[str]]:
    """Each shell command in ``script`` that publishes with npm or cargo, as its
    words from the tool on. Each command, not each line: ``npm publish
    --dry-run && npm publish`` is one line and two publishes. A continued line
    is joined to the next first."""
    found = []
    for command in _COMMAND_END.split(script.replace("\\\n", " ")):
        words = command.split()
        plain = [_unquote(word) for word in words]
        for at, word in enumerate(plain):
            # `npm`, a path to it, or `npm@11.21.1` as npx runs it.
            tool = word.rsplit("/", 1)[-1].split("@", 1)[0]
            if tool in _PUBLISH_WORDS and _PUBLISH_WORDS[tool].intersection(plain[at + 1 :]):
                found.append(words[at:])
                break
    return found


def _is_dry_run(command: list[str]) -> bool:
    # The words as written: a quoted `"--dry-run"`, or one inside another
    # quoted argument, does not count.
    if [word for word in command if _DRY_RUN_OPTION.match(word)] != ["--dry-run"]:
        return False
    # nopt reads the word after a boolean option as its value: `--dry-run false`.
    after = command[command.index("--dry-run") + 1 :]
    return not (after and _unquote(after[0]) == "false")


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
    publishes = [command for run in _runs(workflow) for command in _publishes(run)]
    assert publishes, "the workflow rehearses no publish"
    assert [" ".join(command) for command in publishes if not _is_dry_run(command)] == []


@pytest.mark.parametrize(
    "script",
    [
        "npm publish",
        "npm pu",
        "npm pub --provenance",
        "npm publis --tag next",
        "npm --loglevel=info publish",
        "npm --loglevel info publish",
        'npm "publish"',
        "npx --yes npm@11.21.1 publish",
        "/usr/local/bin/npm publish",
        'echo start\n(cd "${dir}" && npm pub)',
        "npm publish --dry-run && npm publish",
        "npm publish --dry-run || npm pub",
        "npm publish --dry-run; npm publish",
        "npm publish --dry-run | tee log & npm publish",
        "npm \\\n  publish",
        "npm publish --dry-run=false",
        "npm publish --dry-run false",
        "npm publish --dry-run 'false'",
        "npm publish --dry-run --no-dry-run",
        "npm publish --dry-run --no-dry",
        "npm publish --dry-run --dry=false",
        'npm publish --tag "next --dry-run"',
        'npm publish "--dry-run"',
        "cargo publish",
        "cargo +stable publish --locked",
        "cargo --locked publish --manifest-path Cargo.toml",
    ],
)
def test_a_publish_that_is_not_a_dry_run_is_caught(script: str) -> None:
    # npm resolves `pu` to `publis` to `publish` and reads options anywhere on
    # the command line; nopt reads `--no-dry`, `--dry=false` and `--dry-run
    # false` as "not a dry run". Each is a real publish the workflow test must see.
    publishes = _publishes(script)
    assert publishes, script
    assert not all(_is_dry_run(command) for command in publishes), publishes


@pytest.mark.parametrize(
    "script",
    [
        "npm publish --dry-run",
        '(cd "${dir}" && npm publish --dry-run)',
        "npm --dry-run pub",
        "npx --yes npm@11.21.1 publish --dry-run",
        'cargo publish --manifest-path "${MANIFEST}" --locked --dry-run',
        "cargo publish \\\n  --dry-run",
    ],
)
def test_a_dry_run_publish_passes(script: str) -> None:
    publishes = _publishes(script)
    assert publishes, script
    assert all(_is_dry_run(command) for command in publishes), publishes


@pytest.mark.parametrize(
    "script",
    [
        "npm pack --dry-run --json",
        'npm view "${name}@${version}" version',
        "npm install --global npm@11.21.1",
        "npm p",
        'echo "npm publishes a version once"',
        'cargo package --manifest-path "${MANIFEST}" --locked --list',
    ],
)
def test_other_commands_are_not_publishes(script: str) -> None:
    assert _publishes(script) == []


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
    """Every push that changes what is published, nightly and on demand; on a
    pull request, in ci.yml's full set (the `full-ci` label)."""
    triggers = _triggers(workflow)
    paths = triggers["push"]["paths"]
    assert set(paths) >= PUBLISHED_FROM, sorted(PUBLISHED_FROM - set(paths))
    assert triggers["push"]["branches"] == ["development", "integration/unified-core"]
    # No path filter on the pull request: the label must reach the jobs.
    assert triggers["pull_request"] is None
    assert len(triggers["schedule"]) == 1
    assert "workflow_dispatch" in triggers
    for name, job in workflow["jobs"].items():
        assert job.get("if") == FULL_SET, name


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
    release = _load(PACKAGES)
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
    assert check in "\n".join(_runs(_load(PUBLISH), "pypi"))
    assert check in "\n".join(_runs(workflow, "pypi"))
