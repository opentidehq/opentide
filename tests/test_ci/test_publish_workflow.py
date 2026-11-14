"""Contract for ``publish.yml``, the release train (#840): its PyPI job, its
guard, and the modes Run workflow starts (a release, an internal candidate, a
public release candidate, which the guard refuses while the internal channel
exists, a dry run, resuming a tag).

A retry after a PyPI 5xx must be safe. On 0.4.0 the wheel upload got ``502 Bad
Gateway`` but PyPI kept the file, so the version briefly had a wheel and no
sdist. The ``repository_dispatch`` retry only worked because the rebuilt wheel
was byte-identical; with ``skip-existing: false`` any difference would have
failed with ``400 File already exists`` and the sdist could never be published
(#289). scripts/engine/test_release.py holds the rest of the workflow's shape.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
#: The wheels and npm packages, which publish.yml and ci.yml's full set build.
PACKAGES = ROOT / ".github" / "workflows" / "build-packages.yml"
VERIFY_STEP = "Verify PyPI lists every built file"
WEBSITE_WARNING_STEP = "Warn when the website was not notified"
WHEEL = "opentide-9.9.9-py3-none-any.whl"
SDIST = "opentide-9.9.9.tar.gz"


def _workflow() -> dict[Any, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML (YAML 1.1) reads the bare `on` key as boolean True.
    return workflow.get("on", workflow.get(True))


def _steps() -> list[dict[str, Any]]:
    return _workflow()["jobs"]["pypi"]["steps"]


def _step_index(predicate: Any) -> int:
    matches = [index for index, step in enumerate(_steps()) if predicate(step)]
    assert len(matches) == 1, f"expected exactly one matching step, found {matches}"
    return matches[0]


def _publish_index(name: str = "Publish to PyPI") -> int:
    return _step_index(
        lambda step: (
            str(step.get("uses", "")).startswith("pypa/gh-action-pypi-publish@")
            and step.get("name") == name
        )
    )


def _verify_index() -> int:
    return _step_index(lambda step: step.get("name") == VERIFY_STEP)


def test_publish_step_skips_files_pypi_already_has() -> None:
    publish = _steps()[_publish_index("Publish to PyPI")]
    assert publish["with"]["packages-dir"] == "dist/"
    assert publish["with"].get("skip-existing") is True
    uploads = [s for s in _steps() if "pypa/gh-action-pypi-publish@" in str(s.get("uses", ""))]
    assert len(uploads) == 1


def test_a_release_and_a_candidate_both_go_to_pypi() -> None:
    """A candidate is a PyPI pre-release (X.Y.ZrcN), for the Rust-core
    transition: real PyPI, the one trusted publisher, no TestPyPI."""
    steps = _steps()
    pypi = steps[_publish_index("Publish to PyPI")]
    assert "if" not in pypi
    assert "repository-url" not in pypi["with"]
    job = _workflow()["jobs"]["pypi"]
    assert job["environment"]["name"] == "pypi"
    assert job["environment"]["url"] == "https://pypi.org/p/opentide"
    assert job["permissions"] == {"contents": "read", "id-token": "write"}
    verify = steps[_verify_index()]
    assert verify["env"]["PYPI_JSON_BASE"] == "https://pypi.org/pypi"
    assert "test.pypi.org" not in WORKFLOW.read_text(encoding="utf-8")


def test_verify_step_runs_after_upload_and_before_website_notify() -> None:
    steps = _steps()
    verify = _verify_index()
    assert verify == _publish_index("Publish to PyPI") + 1
    assert "continue-on-error" not in steps[verify]
    assert "if" not in steps[verify]
    website = _step_index(lambda step: step.get("id") == "website")
    assert verify < website


def test_the_triggers_are_run_workflow_and_the_resume_dispatch() -> None:
    workflow = _workflow()
    triggers = _triggers(workflow)
    # No `release: published` and no tag push: the train creates its tag.
    assert set(triggers) == {"workflow_dispatch", "repository_dispatch"}
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"internal_candidate", "release_candidate", "dry_run", "checkout_ref"}
    for name in ("internal_candidate", "release_candidate", "checkout_ref"):
        assert inputs[name]["required"] is False
        assert inputs[name]["default"] == ""
    assert inputs["dry_run"]["type"] == "boolean"
    assert inputs["dry_run"]["default"] is False
    assert triggers["repository_dispatch"]["types"] == ["publish"]
    assert workflow["permissions"] == {"contents": "read"}

    # Everything a registry receives is built from one commit: the run's, or
    # the resumed tag's. The guard checks out the run's ref or the tag and
    # resolves it to a commit SHA; every later job checks out that SHA, which
    # neither a moved tag nor a new push can change, and is the only revision
    # build-packages.yml is handed.
    jobs = workflow["jobs"]
    ref = (
        "${{ github.event.inputs.checkout_ref || github.event.client_payload.checkout_ref"
        " || github.sha }}"
    )
    revision = "${{ needs.guard.outputs.revision }}"
    for name, job in jobs.items():
        for step in job.get("steps", []):
            if not str(step.get("uses", "")).startswith("actions/checkout@"):
                continue
            assert step["with"]["persist-credentials"] is False, name
            if name in ("release", "verify-assets"):
                # They read scripts only; the Release targets GITHUB_SHA.
                assert "ref" not in step["with"], name
            elif name == "guard":
                assert step["with"]["ref"] == ref, name
            else:
                assert step["with"]["ref"] == revision, name
                assert "guard" in job["needs"], name
    assert jobs["packages"]["with"]["revision"] == revision
    # The guard compares the checkout with the tag, so it needs the tags.
    guard = next(s for s in jobs["guard"]["steps"] if "actions/checkout@" in str(s.get("uses")))
    assert guard["with"]["fetch-depth"] == 0
    assert jobs["pypi"]["needs"] == ["guard", "verify-assets"]


def test_publish_job_does_not_run_scripts_from_the_checkout() -> None:
    # A dispatch retry checks out an older tag; a helper added to scripts/ after
    # that tag would not exist there and the retry would fail.
    offenders = [
        step.get("name", step.get("uses"))
        for step in _steps()
        if "scripts/" in str(step.get("run", ""))
    ]
    assert offenders == []


def test_website_notify_never_fails_the_publish() -> None:
    steps = _steps()
    token = _step_index(lambda step: step.get("id") == "website")
    notify = _step_index(lambda step: step.get("id") == "notify")
    assert token < notify
    assert steps[token]["continue-on-error"] is True
    assert steps[notify]["continue-on-error"] is True


def test_warns_last_whenever_the_website_was_not_notified() -> None:
    # Both notify steps swallow failures, and a gated-off token step looks
    # identical to a working notify in the run summary (#540).
    steps = _steps()
    warn = _step_index(lambda step: step.get("name") == WEBSITE_WARNING_STEP)
    assert warn == len(steps) - 1
    # No status function: GitHub prepends success(), so a failed publish does
    # not also report a website warning.
    assert steps[warn]["if"] == "steps.notify.outcome != 'success' && env.CHANNEL == 'release'"
    assert "continue-on-error" not in steps[warn]


def test_website_warning_step_gets_every_variable_it_reads() -> None:
    # The warning runs under `set -u` after the upload and without
    # continue-on-error, so a variable the workflow stops passing would turn a
    # release that is already on PyPI red. _run_website_warning sets them all
    # itself and cannot notice.
    job = _workflow()["jobs"]["pypi"]
    step = job["steps"][_step_index(lambda step: step.get("name") == WEBSITE_WARNING_STEP)]
    read = set(re.findall(r"\$\{?([A-Z][A-Z0-9_]*)", step["run"]))
    assert {"RELEASE_TAG", "HAS_WEBSITE_APP", "WEBSITE_TOKEN_OUTCOME", "NOTIFY_OUTCOME"} <= read
    provided = job["env"].keys() | step.get("env", {}).keys()
    assert sorted(read - provided) == []


def _run_website_warning(**env: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to run the workflow step")
    script = _steps()[_step_index(lambda step: step.get("name") == WEBSITE_WARNING_STEP)]["run"]
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        env={"PATH": os.environ.get("PATH", ""), "RELEASE_TAG": "v9.9.9", **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize(
    ("has_id", "has_key", "token", "notify", "reason"),
    [
        ("false", "false", "skipped", "skipped", "but GH_APP_ID and GH_APP_KEY are not set"),
        ("true", "false", "skipped", "skipped", "but GH_APP_KEY is not set"),
        ("false", "true", "skipped", "skipped", "but GH_APP_ID is not set"),
        ("true", "true", "failure", "skipped", "could not mint a GitHub App token"),
        ("true", "true", "success", "failure", "needs contents: write"),
        ("true", "true", "success", "skipped", "token was empty"),
    ],
)
def test_website_warning_names_the_reason_and_the_manual_dispatch(
    has_id: str, has_key: str, token: str, notify: str, reason: str
) -> None:
    result = _run_website_warning(
        # Mirrors the job-level HAS_WEBSITE_APP expression.
        HAS_WEBSITE_APP="true" if has_id == has_key == "true" else "false",
        HAS_GH_APP_ID=has_id,
        HAS_GH_APP_KEY=has_key,
        WEBSITE_TOKEN_OUTCOME=token,
        NOTIFY_OUTCOME=notify,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    warning = result.stdout.splitlines()[0]
    assert warning.startswith("::warning title=Website not notified::v9.9.9 is on PyPI")
    assert reason in warning
    assert "gh api repos/opentidehq/website/dispatches" in result.stdout
    assert "event_type=opentide-released" in result.stdout


class _FakePyPI:
    def __init__(self, responses: list[tuple[int, list[str]]]) -> None:
        self.responses = responses
        self.requests: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                fake.requests.append(self.path)
                index = min(len(fake.requests), len(fake.responses)) - 1
                status, files = fake.responses[index]
                body = json.dumps({"urls": [{"filename": name} for name in files]}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/pypi"

    def __enter__(self) -> _FakePyPI:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def dist(tmp_path: Path) -> Iterator[Path]:
    (tmp_path / "dist").mkdir()
    for name in (WHEEL, SDIST):
        (tmp_path / "dist" / name).write_bytes(b"")
    yield tmp_path


def _run_verify(
    cwd: Path, base: str, *, timeout: str = "0", interval: str = "0"
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to run the workflow step")
    script = _steps()[_verify_index()]["run"]
    env = {
        **os.environ,
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}",
        "PYPI_JSON_BASE": base,
        "VERIFY_TIMEOUT_SECONDS": timeout,
        "VERIFY_INTERVAL_SECONDS": interval,
    }
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_verify_passes_when_pypi_lists_wheel_and_sdist(dist: Path) -> None:
    with _FakePyPI([(200, [WHEEL, SDIST])]) as pypi:
        result = _run_verify(dist, pypi.base)
    assert result.returncode == 0, result.stdout + result.stderr
    assert pypi.requests == ["/pypi/opentide/9.9.9/json"]


def test_verify_fails_with_retry_command_when_sdist_is_missing(dist: Path) -> None:
    with _FakePyPI([(200, [WHEEL])]) as pypi:
        result = _run_verify(dist, pypi.base)
    assert result.returncode == 1
    assert f"The index is missing ['{SDIST}']" in result.stdout
    assert "event_type=publish" in result.stdout
    assert "client_payload[checkout_ref]=v9.9.9" in result.stdout


def test_verify_waits_for_the_cdn_to_catch_up(dist: Path) -> None:
    with _FakePyPI([(404, []), (200, [WHEEL]), (200, [WHEEL, SDIST])]) as pypi:
        result = _run_verify(dist, pypi.base, timeout="30", interval="0.05")
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(pypi.requests) == 3


def test_verify_rejects_a_dist_without_an_sdist(dist: Path) -> None:
    (dist / "dist" / SDIST).unlink()
    with _FakePyPI([(200, [WHEEL])]) as pypi:
        result = _run_verify(dist, pypi.base)
    assert result.returncode == 1
    assert "Expected wheels and one sdist" in result.stdout
    assert pypi.requests == []


# --- The guard: what a run releases ------------------------------------------

GUARD_STEP_ID = "version"
REJECT_STEP = "Reject another version, and missing platforms"
_REPOSITORY = "https://github.com/opentidehq/opentide"


def _job(name: str) -> dict[str, Any]:
    return _workflow()["jobs"][name]


def test_the_release_job_tags_the_built_commit_before_any_registry() -> None:
    release = _job("release")
    assert release["if"] == (
        "needs.guard.outputs.create_release == 'true' && "
        "(needs.guard.outputs.channel == 'release' || needs.guard.outputs.channel == 'rc')"
    )
    # Built, smoke-tested and attested first, so a failed build leaves no tag;
    # the registries, which are permanent, after.
    assert release["needs"] == ["guard", "attest"]
    assert release["permissions"] == {"contents": "write"}
    command = " ".join(release["steps"][-1]["run"].replace("\\\n", " ").split())
    assert 'gh release create "${TAG}" dist/*' in command
    assert '--target "${GITHUB_SHA}"' in command
    assert 'python3 scripts/build/release.py notes "${TAG}"' in command
    # A release is Latest by default (0.4.0 was cut with --latest=false); a
    # candidate is a pre-release that never is.
    assert "flags+=(--prerelease --latest=false)" in command
    assert command.count("--latest") == 1
    assert release["env"]["TAG"] == "${{ needs.guard.outputs.tag }}"


def test_the_guard_reads_every_mode_from_the_inputs() -> None:
    guard = _job("guard")
    assert guard["env"] == {
        "CHECKOUT_REF": (
            "${{ github.event.inputs.checkout_ref || github.event.client_payload.checkout_ref }}"
        ),
        "RELEASE_CANDIDATE": "${{ github.event.inputs.release_candidate }}",
        "INTERNAL_CANDIDATE": "${{ github.event.inputs.internal_candidate }}",
        "DRY_RUN": "${{ github.event.inputs.dry_run }}",
    }
    assert set(guard["outputs"]) == {
        "tag",
        "version",
        "base",
        "pypi_version",
        "channel",
        "create_release",
        "revision",
    }


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        timeout=60,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
        },
    )


def _cargo(version: str) -> str:
    return (
        f'[workspace.package]\nversion = "{version}"\n\n[workspace.dependencies]\n'
        f'opentide-core = {{ path = "crates/opentide-core", version = "={version}" }}\n'
        'opentide-compare = { path = "crates/opentide-compare" }\n'
    )


@pytest.fixture
def development(tmp_path: Path) -> Path:
    """A checkout of development whose notes PR for 1.2.0 has merged, the
    crates bumped to it."""
    if shutil.which("git") is None:
        pytest.skip("git is required")
    repo = tmp_path / "repo"
    files = {
        "CHANGELOG.md": "## [Unreleased]\n\n- **A change.**\n\n## [1.2.0] — 2026-11-02\n\n"
        f"[Unreleased]: {_REPOSITORY}/compare/v1.2.0...HEAD\n"
        f"[1.2.0]: {_REPOSITORY}/releases/tag/v1.2.0\n",
        ".github/release-notes/v1.2.0.md": "# 1.2.0\n",
        "docs/usage/releases.md": "## 1.2.0 — 2 November 2026\n",
        "README.md": "pip install opentide==1.2.0\n",
        "Cargo.toml": _cargo("1.2.0"),
    }
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    for script in ("build", "engine"):
        (repo / "scripts" / script).mkdir(parents=True)
        shutil.copy(ROOT / "scripts" / script / "release.py", repo / "scripts" / script)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "notes")
    return repo


#: The guard's one-line switch for public release candidates.
PUBLIC_CANDIDATES_OFF = "public_candidates=false\n"


def _run_guard(
    repo: Path, *, gh_has_release: bool = False, public_candidates: bool = False, **env: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to run the workflow step")
    steps = _job("guard")["steps"]
    script = next(step for step in steps if step.get("id") == GUARD_STEP_ID)["run"]
    assert script.count(PUBLIC_CANDIDATES_OFF) == 1
    if public_candidates:
        # The public candidate's paths, as re-enabling them would run them.
        script = script.replace(PUBLIC_CANDIDATES_OFF, "public_candidates=true\n")
    stubs = repo.parent / "bin"
    stubs.mkdir(exist_ok=True)
    # `gh release view` answers whether the Release exists; `python` is this one.
    (stubs / "gh").write_text(f"#!/bin/sh\nexit {0 if gh_has_release else 1}\n", encoding="utf-8")
    (stubs / "gh").chmod(0o755)
    # A wrapper, not a symlink: a virtualenv's interpreter finds its pyvenv.cfg
    # beside the path it is run as, so a symlink here would run the base
    # interpreter without the venv's packages (tomli, on Python 3.10).
    (stubs / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    (stubs / "python").chmod(0o755)
    output = repo.parent / "github_output"
    output.write_text("", encoding="utf-8")
    summary = repo.parent / "summary"
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=repo,
        env={
            "PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
            "GITHUB_REPOSITORY": "opentidehq/opentide",
            "GITHUB_REF": "refs/heads/development",
            "GITHUB_REF_NAME": "development",
            "CHECKOUT_REF": "",
            "RELEASE_CANDIDATE": "",
            "INTERNAL_CANDIDATE": "",
            "DRY_RUN": "false",
            **env,
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    outputs = dict(
        line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines() if line
    )
    if outputs:
        # The commit every later job builds: the guard's checkout, as its SHA.
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()
        assert outputs.pop("revision") == head
    return result, outputs


def test_the_guard_releases_the_version_the_changelog_names(development: Path) -> None:
    result, outputs = _run_guard(development)
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs == {
        "tag": "v1.2.0",
        "version": "1.2.0",
        "base": "1.2.0",
        "pypi_version": "1.2.0",
        "channel": "release",
        "create_release": "true",
    }


def test_the_guard_refuses_crates_at_another_version(development: Path) -> None:
    """Lockstep: one product version, or nothing is released."""
    (development / "Cargo.toml").write_text(_cargo("1.1.0"), encoding="utf-8")
    result, outputs = _run_guard(development)
    assert result.returncode == 1
    assert "the workspace version in Cargo.toml is 1.1.0, not 1.2.0" in result.stderr
    assert "release.py bump 1.2.0" in result.stderr
    assert outputs == {}


def test_the_guard_releases_only_from_development(development: Path) -> None:
    result, outputs = _run_guard(
        development, GITHUB_REF="refs/heads/feature", GITHUB_REF_NAME="feature"
    )
    assert result.returncode == 1
    assert "Run the release from development, not feature" in result.stderr
    assert outputs == {}


@pytest.mark.parametrize("branch", ["integration/unified-core", "feature"])
def test_a_release_from_another_branch_is_refused(development: Path, branch: str) -> None:
    """Only a candidate may run from integration/unified-core: a release is development's."""
    result, outputs = _run_guard(
        development, GITHUB_REF=f"refs/heads/{branch}", GITHUB_REF_NAME=branch
    )
    assert result.returncode == 1
    assert f"Run the release from development, not {branch}" in result.stderr
    assert outputs == {}


@pytest.mark.parametrize("branch", ["integration/unified-core", "development"])
def test_a_candidate_runs_from_integration_or_development(development: Path, branch: str) -> None:
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    result, outputs = _run_guard(
        development,
        public_candidates=True,
        RELEASE_CANDIDATE="1",
        GITHUB_REF=f"refs/heads/{branch}",
        GITHUB_REF_NAME=branch,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs["tag"] == "v1.3.0-rc.1"
    assert outputs["version"] == "1.3.0-rc.1"
    assert outputs["pypi_version"] == "1.3.0rc1"
    assert outputs["channel"] == "rc"
    assert outputs["create_release"] == "true"


@pytest.mark.parametrize("branch", ["feature", "main", "integration/other"])
def test_a_candidate_from_another_branch_is_refused(development: Path, branch: str) -> None:
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    result, outputs = _run_guard(
        development,
        public_candidates=True,
        RELEASE_CANDIDATE="1",
        GITHUB_REF=f"refs/heads/{branch}",
        GITHUB_REF_NAME=branch,
    )
    assert result.returncode == 1
    assert (
        f"Run a release candidate from integration/unified-core or development, not {branch}"
        in result.stderr
    )
    assert outputs == {}


def test_a_candidate_from_integration_must_be_above_the_last_release(development: Path) -> None:
    """check-candidate holds on integration/unified-core as on development."""
    result, outputs = _run_guard(
        development,
        public_candidates=True,
        RELEASE_CANDIDATE="1",
        GITHUB_REF="refs/heads/integration/unified-core",
        GITHUB_REF_NAME="integration/unified-core",
    )
    assert result.returncode == 1
    assert "1.2.0 is not newer than 1.2.0" in result.stderr
    assert outputs == {}


def test_the_guard_refuses_a_version_already_tagged(development: Path) -> None:
    _git(development, "tag", "v1.2.0")
    result, outputs = _run_guard(development)
    assert result.returncode == 1
    assert "v1.2.0 is already tagged" in result.stderr
    assert "checkout_ref=v1.2.0" in result.stderr
    assert outputs == {}


def test_the_guard_refuses_a_version_already_released(development: Path) -> None:
    # A Release whose tag this checkout did not fetch.
    result, outputs = _run_guard(development, gh_has_release=True)
    assert result.returncode == 1
    assert "v1.2.0 is already tagged" in result.stderr
    assert outputs == {}


def test_the_guard_refuses_before_the_notes_pr_merges(development: Path) -> None:
    (development / ".github" / "release-notes" / "v1.2.0.md").unlink()
    result, outputs = _run_guard(development)
    assert result.returncode == 1
    assert ".github/release-notes/v1.2.0.md is missing" in result.stderr
    assert outputs == {}


def test_a_candidate_is_of_the_bumped_workspace_version(development: Path) -> None:
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    result, outputs = _run_guard(development, public_candidates=True, RELEASE_CANDIDATE="2")
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs == {
        "tag": "v1.3.0-rc.2",
        "version": "1.3.0-rc.2",
        "base": "1.3.0",
        "pypi_version": "1.3.0rc2",
        "channel": "rc",
        "create_release": "true",
    }


def test_a_candidate_of_a_released_version_is_refused(development: Path) -> None:
    result, outputs = _run_guard(development, public_candidates=True, RELEASE_CANDIDATE="1")
    assert result.returncode == 1
    assert "1.2.0 is not newer than 1.2.0" in result.stderr
    assert outputs == {}
    result, _ = _run_guard(development, RELEASE_CANDIDATE="x")
    assert result.returncode == 1
    assert "release_candidate is a number from 1" in result.stderr


def test_a_dry_run_runs_anywhere_and_creates_nothing(development: Path) -> None:
    result, outputs = _run_guard(
        development, DRY_RUN="true", GITHUB_REF="refs/heads/feature", GITHUB_REF_NAME="feature"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs["channel"] == "dry-run"
    assert outputs["create_release"] == "false"
    assert outputs["tag"] == "v1.2.0"


def test_resuming_needs_the_tag_and_its_release(development: Path) -> None:
    result, _ = _run_guard(development, CHECKOUT_REF="v1.2.0")
    assert result.returncode == 1
    assert "must be an existing release tag" in result.stderr
    _git(development, "tag", "v1.2.0")
    result, _ = _run_guard(development, CHECKOUT_REF="v1.2.0")
    assert result.returncode == 1
    assert "has no GitHub Release to resume" in result.stderr
    result, outputs = _run_guard(development, CHECKOUT_REF="v1.2.0", gh_has_release=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs["channel"] == "release"
    assert outputs["create_release"] == "false"


# --- The internal channel: a tag and a draft, no registry --------------------

#: The jobs that publish, attest or check what was published: none may run for
#: an internal candidate (or a dry run).
PUBLISHING_JOBS = (
    "attest",
    "release",
    "verify-assets",
    "pypi",
    "crates",
    "npm",
    "smoke-registries",
)


@pytest.mark.parametrize("branch", ["integration/unified-core", "development"])
def test_an_internal_candidate_runs_from_integration_or_development(
    development: Path, branch: str
) -> None:
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    result, outputs = _run_guard(
        development,
        INTERNAL_CANDIDATE="2",
        GITHUB_REF=f"refs/heads/{branch}",
        GITHUB_REF_NAME=branch,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs == {
        "tag": "v1.3.0-rc.2",
        "version": "1.3.0-rc.2",
        "base": "1.3.0",
        "pypi_version": "1.3.0rc2",
        "channel": "internal",
        # The `release` job never runs for it; `internal-release` drafts it.
        "create_release": "false",
    }


@pytest.mark.parametrize("branch", ["feature", "main", "integration/other"])
def test_an_internal_candidate_from_another_branch_is_refused(
    development: Path, branch: str
) -> None:
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    result, outputs = _run_guard(
        development,
        INTERNAL_CANDIDATE="1",
        GITHUB_REF=f"refs/heads/{branch}",
        GITHUB_REF_NAME=branch,
    )
    assert result.returncode == 1
    assert (
        f"Run an internal candidate from integration/unified-core or development, not {branch}"
        in result.stderr
    )
    assert outputs == {}


@pytest.mark.parametrize(
    "other", [{"RELEASE_CANDIDATE": "1"}, {"DRY_RUN": "true"}, {"CHECKOUT_REF": "v1.2.0"}]
)
def test_an_internal_candidate_combines_with_no_other_mode(
    development: Path, other: dict[str, str]
) -> None:
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    _git(development, "tag", "v1.2.0")
    result, outputs = _run_guard(development, gh_has_release=True, INTERNAL_CANDIDATE="1", **other)
    assert result.returncode == 1
    assert (
        "internal_candidate cannot be combined with release_candidate, dry_run or checkout_ref"
        in result.stderr
    )
    assert outputs == {}


def test_an_internal_candidate_is_checked_as_a_candidate(development: Path) -> None:
    """check-candidate, the number, an existing tag or Release, and lockstep."""
    result, outputs = _run_guard(development, INTERNAL_CANDIDATE="1")
    assert result.returncode == 1
    assert "1.2.0 is not newer than 1.2.0" in result.stderr
    assert outputs == {}
    result, _ = _run_guard(development, INTERNAL_CANDIDATE="0")
    assert result.returncode == 1
    assert "internal_candidate is a number from 1, not 0" in result.stderr
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    result, _ = _run_guard(development, gh_has_release=True, INTERNAL_CANDIDATE="1")
    assert result.returncode == 1
    assert "v1.3.0-rc.1 is already tagged" in result.stderr
    assert "internal_candidate=2" in result.stderr
    _git(development, "tag", "v1.3.0-rc.1")
    result, _ = _run_guard(development, INTERNAL_CANDIDATE="1")
    assert result.returncode == 1
    assert "v1.3.0-rc.1 is already tagged" in result.stderr


def test_an_internal_candidate_needs_the_crates_at_its_version(development: Path) -> None:
    (development / "Cargo.toml").write_text(
        _cargo("1.3.0").replace('version = "=1.3.0"', 'version = "=1.2.0"'), encoding="utf-8"
    )
    result, outputs = _run_guard(development, INTERNAL_CANDIDATE="1")
    assert result.returncode == 1
    assert "opentide-core is pinned to =1.2.0, not =1.3.0" in result.stderr
    assert outputs == {}


@pytest.mark.parametrize("branch", ["integration/unified-core", "development"])
def test_a_public_release_candidate_is_refused(development: Path, branch: str) -> None:
    """Public candidates (PyPI and crates.io pre-releases) are disabled while
    the internal channel exists; the guard points at internal_candidate."""
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    result, outputs = _run_guard(
        development,
        RELEASE_CANDIDATE="1",
        GITHUB_REF=f"refs/heads/{branch}",
        GITHUB_REF_NAME=branch,
    )
    assert result.returncode == 1
    assert (
        "public release candidates are disabled while the internal channel exists: "
        "run internal_candidate=1 instead"
    ) in result.stderr
    assert outputs == {}


def test_a_public_release_candidate_may_still_be_rehearsed(development: Path) -> None:
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    result, outputs = _run_guard(
        development,
        RELEASE_CANDIDATE="1",
        DRY_RUN="true",
        GITHUB_REF="refs/heads/feature",
        GITHUB_REF_NAME="feature",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs["channel"] == "dry-run"
    assert outputs["tag"] == "v1.3.0-rc.1"
    assert outputs["create_release"] == "false"


def test_a_candidates_tag_is_not_resumed_to_the_registries(development: Path) -> None:
    """An internal candidate's tag must never reach PyPI or crates.io through
    checkout_ref; with public candidates on, a candidate's tag resumes."""
    (development / "Cargo.toml").write_text(_cargo("1.3.0"), encoding="utf-8")
    _git(development, "tag", "v1.3.0-rc.1")
    result, outputs = _run_guard(development, gh_has_release=True, CHECKOUT_REF="v1.3.0-rc.1")
    assert result.returncode == 1
    assert "public release candidates are disabled" in result.stderr
    assert outputs == {}
    result, outputs = _run_guard(
        development, gh_has_release=True, public_candidates=True, CHECKOUT_REF="v1.3.0-rc.1"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs["channel"] == "rc"


def _channels_allowed(condition: str) -> set[str]:
    """The guard channels for which a job's `if` can hold: every channel is
    substituted in turn, the rest of the condition taken as true."""
    allowed = set()
    for channel in ("release", "rc", "internal", "dry-run"):
        expression = condition.removeprefix("${{").removesuffix("}}").strip()
        expression = expression.replace("needs.guard.outputs.channel", repr(channel))
        expression = re.sub(r"!cancelled\(\)", "True", expression)
        expression = re.sub(r"needs\.[\w-]+\.result == '\w+'", "True", expression)
        expression = re.sub(r"needs\.guard\.outputs\.\w+ == '\w+'", "True", expression)
        expression = expression.replace("&&", " and ").replace("||", " or ")
        assert re.fullmatch(r"[\w'\-=!() ]+", expression), expression
        if eval(expression, {"__builtins__": {}}, {"True": True}):
            allowed.add(channel)
    return allowed


def test_no_job_publishes_attests_or_mints_a_token_for_an_internal_candidate() -> None:
    jobs = _workflow()["jobs"]
    for name in PUBLISHING_JOBS:
        # Explicit, not through a skipped dependency: each job's own `if`.
        assert _channels_allowed(jobs[name]["if"]) <= {"release", "rc"}, name
    assert _channels_allowed(jobs["npm"]["if"]) == {"release"}
    assert _channels_allowed(jobs["internal-release"]["if"]) == {"internal"}
    # Every job that holds an OIDC token is one of those; every other job that
    # can run for an internal candidate holds none.
    minting = {
        name for name, job in jobs.items() if job.get("permissions", {}).get("id-token") == "write"
    }
    assert minting == {"attest", "pypi", "crates", "npm"}
    for name, job in jobs.items():
        if name not in PUBLISHING_JOBS:
            assert "id-token" not in job.get("permissions", {}), name
    assert "id-token" not in _workflow()["permissions"]


def test_the_internal_release_drafts_a_tagged_pre_release_after_every_smoke_test() -> None:
    jobs = _workflow()["jobs"]
    job = jobs["internal-release"]
    assert job["permissions"] == {"contents": "write"}
    assert job["if"] == "needs.guard.outputs.channel == 'internal'"
    # The same builds, and every smoke test, pass first.
    smokes = {name for name in jobs if name.startswith("smoke-") and name != "smoke-registries"}
    assert {"guard", "checks", "release-assets", "packages", "sdist", *smokes} <= set(job["needs"])
    assert set(jobs["attest"]["needs"]) == set(job["needs"])
    downloads = [s["with"] for s in job["steps"] if "download-artifact@" in str(s.get("uses"))]
    assert {d.get("name") or d.get("pattern") for d in downloads} == {
        "release-assets",
        "wheels-*",
        "sdist",
        "crates",
        "npm-packages",
    }
    run = " ".join(
        " ".join(str(s.get("run", "")) for s in job["steps"]).replace("\\\n", " ").split()
    )
    # The tag first (a draft does not create it), on the commit built.
    tag = (
        'gh api "repos/${GITHUB_REPOSITORY}/git/refs"'
        ' -f ref="refs/tags/${TAG}" -f sha="${REVISION}"'
    )
    assert tag in run
    assert job["env"]["REVISION"] == "${{ needs.guard.outputs.revision }}"
    create = run[run.index("gh release create") :]
    assert run.index(tag) < run.index("gh release create")
    for flag in ("--draft", "--prerelease", "--verify-tag", "--latest=false"):
        assert flag in create, flag
    assert 'python3 scripts/build/release.py notes --internal "${TAG}"' in run
    # Nothing that reaches a registry, and no attestation.
    for word in ("pypi-publish", "cargo publish", "release.py publish", "npm publish", "attest"):
        assert word not in run, word


def _run_gather(tmp_path: Path, files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None or shutil.which("sha256sum") is None:
        pytest.skip("bash and sha256sum are required to run the workflow step")
    steps = _job("internal-release")["steps"]
    script = next(s for s in steps if str(s.get("name", "")).startswith("Gather"))["run"]
    for name, text in files.items():
        (tmp_path / "dist" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "dist" / name).write_text(text, encoding="utf-8")
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        env={"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


_BUILT = {
    "release/SHA256SUMS": "sums",
    "release/opentide-v1.3.0-rc.1-x86_64-unknown-linux-gnu.tar.gz": "bin",
    "python/opentide-1.3.0rc1-cp310-abi3-win_amd64.whl": "wheel",
    "python/opentide-1.3.0rc1.tar.gz": "sdist",
    "crates/opentide-1.3.0-rc.1.crate": "crate",
    "npm/1-native/opentide-opentide-linux-x64-gnu-1.3.0-rc.1.tgz": "native",
    "npm/2-package/opentide-opentide-1.3.0-rc.1.tgz": "package",
}


def test_the_internal_release_flattens_the_packages_and_sums_them(tmp_path: Path) -> None:
    result = _run_gather(tmp_path, _BUILT)
    assert result.returncode == 0, result.stdout + result.stderr
    upload = tmp_path / "upload"
    names = {path.name for path in upload.iterdir()}
    assert names == {Path(name).name for name in _BUILT} | {"PACKAGES-SHA256SUMS"}
    # The release assets' own SHA256SUMS is untouched; the packages get theirs.
    assert (upload / "SHA256SUMS").read_text(encoding="utf-8") == "sums"
    listed = (upload / "PACKAGES-SHA256SUMS").read_text(encoding="utf-8").splitlines()
    packages = sorted(Path(name).name for name in _BUILT if not name.startswith("release/"))
    assert sorted(line.split()[1] for line in listed) == packages
    check = subprocess.run(
        ["sha256sum", "--check", "--strict", "PACKAGES-SHA256SUMS"],
        cwd=upload,
        capture_output=True,
        text=True,
        check=False,
    )
    assert check.returncode == 0, check.stdout + check.stderr


def test_the_internal_release_fails_on_a_name_collision(tmp_path: Path) -> None:
    built = {**_BUILT, "npm/3-alias/opentide-opentide-1.3.0-rc.1.tgz": "alias"}
    result = _run_gather(tmp_path, built)
    assert result.returncode == 1
    assert "two assets are named opentide-opentide-1.3.0-rc.1.tgz" in result.stderr


def _run_reject(cwd: Path, expected: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to run the workflow step")
    step = _steps()[_step_index(lambda step: step.get("name") == REJECT_STEP)]
    assert step["env"]["EXPECTED_VERSION"] == "${{ needs.guard.outputs.pypi_version }}"
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
        cwd=cwd,
        env={
            "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}",
            "EXPECTED_VERSION": expected,
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.fixture
def platform_dist(tmp_path: Path) -> Path:
    (tmp_path / "dist").mkdir()
    for platform in (
        "manylinux_2_28_x86_64",
        "manylinux_2_28_aarch64",
        "macosx_10_12_x86_64",
        "macosx_11_0_arm64",
        "win_amd64",
        "win_arm64",
    ):
        (tmp_path / "dist" / f"opentide-1.2.0-cp310-abi3-{platform}.whl").write_bytes(b"")
    (tmp_path / "dist" / "opentide-1.2.0.tar.gz").write_bytes(b"")
    return tmp_path


def test_publish_accepts_the_version_the_guard_approved(platform_dist: Path) -> None:
    result = _run_reject(platform_dist, "1.2.0")
    assert result.returncode == 0, result.stdout + result.stderr


def test_publish_refuses_files_of_another_version_than_the_guard_approved(
    platform_dist: Path,
) -> None:
    result = _run_reject(platform_dist, "1.3.0")
    assert result.returncode == 1
    assert "built ['1.2.0'], but the guard approved 1.3.0" in result.stdout


def test_publish_refuses_a_release_without_a_windows_on_arm_wheel(platform_dist: Path) -> None:
    """Windows on Arm fell back to the sdist, which needs Rust (#748)."""
    (platform_dist / "dist" / "opentide-1.2.0-cp310-abi3-win_arm64.whl").unlink()
    result = _run_reject(platform_dist, "1.2.0")
    assert result.returncode == 1
    assert "Refusing to publish: no win arm64 wheel" in result.stdout


def test_publish_refuses_a_release_without_a_linux_arm_wheel(platform_dist: Path) -> None:
    (platform_dist / "dist" / "opentide-1.2.0-cp310-abi3-manylinux_2_28_aarch64.whl").unlink()
    result = _run_reject(platform_dist, "1.2.0")
    assert result.returncode == 1
    assert "Refusing to publish: no manylinux aarch64 wheel" in result.stdout


def test_publish_refuses_a_musllinux_wheel(platform_dist: Path) -> None:
    """No musl builds: the maintainer's decision (docs/internal/publishing.md)."""
    (platform_dist / "dist" / "opentide-1.2.0-cp310-abi3-musllinux_1_2_x86_64.whl").write_bytes(b"")
    result = _run_reject(platform_dist, "1.2.0")
    assert result.returncode == 1
    assert "a musllinux wheel" in result.stdout


def _pyproject() -> dict[str, Any]:
    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover - Python 3.10
        import tomli as tomllib

    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_cibuildwheel_builds_no_musllinux_wheel() -> None:
    config = _pyproject()["tool"]["cibuildwheel"]
    assert "*-musllinux_*" in config["skip"]
    assert config["linux"]["manylinux-x86_64-image"] == "manylinux_2_28"
    assert config["linux"]["manylinux-aarch64-image"] == "manylinux_2_28"
    # One stable-ABI build: the free-threaded CPython (3.14t) builds the sdist.
    assert config["build"] == "cp310-*"


def _packages() -> dict[Any, Any]:
    return yaml.safe_load(PACKAGES.read_text(encoding="utf-8"))


def _wheel_steps() -> list[dict[str, Any]]:
    return _packages()["jobs"]["wheels"]["steps"]


def test_wheels_are_built_on_windows_on_arm() -> None:
    matrix = _packages()["jobs"]["wheels"]["strategy"]["matrix"]["include"]
    runners = {entry["os"]: entry["platform"] for entry in matrix}
    assert runners["windows-11-arm"] == "windows-arm64"
    assert runners["windows-latest"] == "windows-x64"


def test_the_packages_build_only_a_validated_commit_sha() -> None:
    """build-packages.yml takes one revision, a 40-hex SHA it checks before any
    checkout: no branch or tag name, which could move or name untrusted code."""
    workflow = _packages()
    inputs = _triggers(workflow)["workflow_call"]["inputs"]
    assert inputs["revision"]["required"] is True
    assert "ref" not in inputs
    jobs = workflow["jobs"]
    steps = jobs["versions"]["steps"]
    check = next(i for i, s in enumerate(steps) if s.get("name") == "The revision is a commit SHA")
    first_checkout = next(
        i for i, s in enumerate(steps) if "actions/checkout@" in str(s.get("uses"))
    )
    assert check < first_checkout
    assert steps[check]["env"] == {"REVISION": "${{ inputs.revision }}"}
    for name, job in jobs.items():
        for step in job.get("steps", []):
            if "actions/checkout@" in str(step.get("uses")):
                assert step["with"] == {
                    "persist-credentials": False,
                    "ref": "${{ inputs.revision }}",
                }, name
        if name != "versions":
            needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
            # Every job waits for the check, directly or through another job.
            assert set(needs) & {"versions", "npm-native", "npm-pack"}, name
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    assert ci["jobs"]["packages"]["with"]["revision"] == "${{ github.sha }}"


@pytest.mark.parametrize(
    ("revision", "accepted"),
    [
        ("0123456789abcdef0123456789abcdef01234567", True),
        ("0123456789abcdef", False),
        ("0123456789ABCDEF0123456789ABCDEF01234567", False),
        ("v1.2.3", False),
        ("development", False),
        ("refs/pull/1/head", False),
        ("0123456789abcdef0123456789abcdef01234567\nmain", False),
        ("", False),
    ],
)
def test_the_revision_check(revision: str, accepted: bool) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to run the workflow step")
    steps = _packages()["jobs"]["versions"]["steps"]
    script = next(s for s in steps if s.get("name") == "The revision is a commit SHA")["run"]
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-c", script],
        env={"PATH": os.environ.get("PATH", ""), "REVISION": revision},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is accepted, result.stderr


def test_publish_builds_the_packages_with_the_reusable_workflow() -> None:
    """publish.yml and ci.yml's full set build the wheels and npm packages
    with one workflow, so what a maintainer tests is what a release ships."""
    job = _job("packages")
    assert job["uses"] == "./.github/workflows/build-packages.yml"
    assert job["needs"] == ["guard", "checks"]
    assert job["permissions"] == {"contents": "read"}
    assert job["with"]["pypi-version"] == "${{ needs.guard.outputs.pypi_version }}"
    assert job["with"]["npm-version"] == "${{ needs.guard.outputs.version }}"
    for name in ("wheels", "npm-native", "npm-pack"):
        assert name not in _workflow()["jobs"], name


def test_the_windows_on_arm_wheel_is_installed_and_doctor_runs() -> None:
    """cibuildwheel skips testing it, so the workflow installs it itself (#748)."""
    pyproject = _pyproject()
    assert pyproject["tool"]["cibuildwheel"]["test-skip"] == "*-win_arm64"
    names = [step.get("name") for step in _wheel_steps()]
    build = names.index("Build wheels")
    smoke = names.index("Install the win_arm64 wheel and run doctor")
    rust = names.index("Rust on Windows on Arm")
    assert rust < build < smoke
    step = _wheel_steps()[smoke]
    assert step["if"] == "matrix.os == 'windows-11-arm'"
    # The package depends on pydantic alone (UC-6.2): no cryptography to pin to a wheel.
    assert "env" not in step
    script = step["run"]
    assert "$PSNativeCommandUseErrorActionPreference = $true" in script
    assert "*-cp310-abi3-win_arm64.whl" in script
    assert "--json doctor --offline" in script
    assert "--json setup --path $workspace --yes" in script
    # The slim package's smoke, as smoke-wheel's: the version, the
    # requirements, validate on the tide corpus and the SDK.
    assert (
        "& $python -I scripts/build/smoke_package.py $env:SETUPTOOLS_SCM_PRETEND_VERSION" in script
    )


@pytest.mark.parametrize("job", ["smoke-wheel", "smoke-sdist"])
def test_the_smoke_tests_run_the_package_smoke_on_the_installed_package(job: str) -> None:
    """pip install, then scripts/build/smoke_package.py with the venv's Python:
    `opentide --version`, the requirements against pyproject.toml (pydantic
    alone), `--json validate` on the tide corpus and the SDK."""
    steps = _job(job)["steps"]
    checkout = next(i for i, s in enumerate(steps) if "actions/checkout@" in str(s.get("uses")))
    run = next(i for i, s in enumerate(steps) if "smoke_package.py" in str(s.get("run", "")))
    assert checkout < run
    assert steps[checkout]["with"]["persist-credentials"] is False
    script = steps[run]["run"]
    assert "set -euo pipefail" in script
    assert 'python" -I scripts/build/smoke_package.py "${PYPI_VERSION}"' in script
    assert "pip install --quiet" in script
    # Every action stays pinned by commit SHA.
    for job in [*_workflow()["jobs"].values(), *_packages()["jobs"].values()]:
        for item in job.get("steps", []):
            if "uses" in item:
                assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", item["uses"]), item["uses"]
