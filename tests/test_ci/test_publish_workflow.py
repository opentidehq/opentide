"""Contract for ``publish-pypi.yml``: a retry after a PyPI 5xx must be safe.

On 0.4.0 the wheel upload got ``502 Bad Gateway`` but PyPI kept the file, so
the version briefly had a wheel and no sdist. The ``repository_dispatch`` retry
only worked because the rebuilt wheel was byte-identical; with
``skip-existing: false`` any difference would have failed with ``400 File
already exists`` and the sdist could never be published (#289).
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
WORKFLOW = ROOT / ".github" / "workflows" / "publish-pypi.yml"
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
    return _workflow()["jobs"]["publish"]["steps"]


def _step_index(predicate: Any) -> int:
    matches = [index for index, step in enumerate(_steps()) if predicate(step)]
    assert len(matches) == 1, f"expected exactly one matching step, found {matches}"
    return matches[0]


def _publish_index() -> int:
    return _step_index(
        lambda step: str(step.get("uses", "")).startswith("pypa/gh-action-pypi-publish@")
    )


def _verify_index() -> int:
    return _step_index(lambda step: step.get("name") == VERIFY_STEP)


def test_publish_step_skips_files_pypi_already_has() -> None:
    publish = _steps()[_publish_index()]
    assert publish["with"]["packages-dir"] == "dist/"
    assert publish["with"].get("skip-existing") is True


def test_verify_step_runs_after_upload_and_before_website_notify() -> None:
    steps = _steps()
    verify = _verify_index()
    assert verify == _publish_index() + 1
    assert "continue-on-error" not in steps[verify]
    assert "if" not in steps[verify]
    website = _step_index(lambda step: step.get("id") == "website")
    assert verify < website


def test_retry_triggers_and_checkout_ref_stay_wired() -> None:
    workflow = _workflow()
    triggers = _triggers(workflow)
    assert triggers["release"]["types"] == ["published"]
    # Optional: empty releases development, a tag re-publishes it.
    checkout_ref_input = triggers["workflow_dispatch"]["inputs"]["checkout_ref"]
    assert checkout_ref_input["required"] is False
    assert checkout_ref_input["default"] == ""
    assert triggers["repository_dispatch"]["types"] == ["publish-pypi"]
    assert workflow["permissions"] == {"contents": "read", "id-token": "write"}

    # The publish job uploads what the build jobs built: every checkout, in
    # the guard and the wheel and sdist builds, takes the retry's tag.
    checkouts = {
        name: step
        for name, job in workflow["jobs"].items()
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    }
    assert set(checkouts) == {"guard", "wheels", "sdist", "release"}
    for name in ("guard", "wheels", "sdist"):
        ref = checkouts[name]["with"]["ref"]
        assert "github.event.client_payload.checkout_ref" in ref
        assert "github.event.inputs.checkout_ref" in ref
        # Releasing development builds the commit the run started on.
        assert ref.endswith("|| github.sha }}")
    # The Release is tagged on that same commit; it only reads the notes.
    assert checkouts["release"]["with"] == {
        "ref": "${{ github.sha }}",
        "sparse-checkout": ".github/release-notes",
    }
    # The guard compares the checkout with the tag, so it needs the tags.
    assert checkouts["guard"]["with"]["fetch-depth"] == 0
    assert workflow["jobs"]["publish"]["needs"] == ["guard", "wheels", "sdist", "release"]


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
    assert steps[warn]["if"] == "steps.notify.outcome != 'success'"
    assert "continue-on-error" not in steps[warn]


def test_website_warning_step_gets_every_variable_it_reads() -> None:
    # The warning runs under `set -u` after the upload and without
    # continue-on-error, so a variable the workflow stops passing would turn a
    # release that is already on PyPI red. _run_website_warning sets them all
    # itself and cannot notice.
    job = _workflow()["jobs"]["publish"]
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
    assert f"PyPI is missing ['{SDIST}']" in result.stdout
    assert "event_type=publish-pypi" in result.stdout
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


# --- Releasing from development (Run workflow, checkout_ref empty) -----------

GUARD_STEP_ID = "version"
REJECT_STEP = "Reject untagged / dev versions, and missing platforms"
_REPOSITORY = "https://github.com/opentidehq/opentide"


def _job(name: str) -> dict[str, Any]:
    return _workflow()["jobs"][name]


def test_the_release_job_tags_the_built_commit_before_pypi() -> None:
    workflow = _workflow()
    release = _job("release")
    # Only a run that releases development creates a Release; a published
    # Release or a checkout_ref retry already has its tag.
    assert release["if"] == "needs.guard.outputs.create_release == 'true'"
    # Built first, so a failed build leaves no tag; PyPI, which is permanent, after.
    assert release["needs"] == ["guard", "wheels", "sdist"]
    assert "release" in workflow["jobs"]["publish"]["needs"]
    # Write access on this job only; the publish job keeps contents: read.
    assert release["permissions"] == {"contents": "write"}
    assert workflow["permissions"] == {"contents": "read", "id-token": "write"}
    assert "permissions" not in workflow["jobs"]["publish"]
    command = " ".join(release["steps"][-1]["run"].replace("\\\n", " ").split())
    assert 'gh release create "${RELEASE_TAG}"' in command
    assert '--target "${GITHUB_SHA}"' in command
    assert '--notes-file ".github/release-notes/${RELEASE_TAG}.md"' in command
    # The newest version must become Latest (0.4.0 was cut with --latest=false).
    assert "--latest" not in command
    assert release["env"]["RELEASE_TAG"] == "${{ needs.guard.outputs.tag }}"


def test_publish_runs_after_a_skipped_release_job_but_not_a_failed_one() -> None:
    condition = " ".join(_job("publish")["if"].split())
    assert condition.startswith("!cancelled()")
    assert "needs.wheels.result == 'success'" in condition
    assert "needs.sdist.result == 'success'" in condition
    assert "(needs.release.result == 'success' || needs.release.result == 'skipped')" in condition
    # Every tag the publish job names comes from the guard, in every mode.
    assert _job("publish")["env"]["RELEASE_TAG"] == "${{ needs.guard.outputs.tag }}"


def test_the_guard_decides_the_mode_from_an_empty_checkout_ref() -> None:
    guard = _job("guard")
    assert guard["env"]["FROM_BRANCH"] == (
        "${{ github.event_name == 'workflow_dispatch' && github.event.inputs.checkout_ref == '' }}"
    )
    assert guard["outputs"] == {
        "version": "${{ steps.version.outputs.version }}",
        "tag": "${{ steps.version.outputs.tag }}",
        "create_release": "${{ steps.version.outputs.create_release }}",
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


@pytest.fixture
def development(tmp_path: Path) -> Path:
    """A checkout of development whose notes PR for 1.2.0 has merged."""
    if shutil.which("git") is None:
        pytest.skip("git is required")
    repo = tmp_path / "repo"
    files = {
        "CHANGELOG.md": "## [Unreleased]\n\n## [1.2.0] — 2026-11-02\n\n"
        f"[Unreleased]: {_REPOSITORY}/compare/v1.2.0...HEAD\n"
        f"[1.2.0]: {_REPOSITORY}/releases/tag/v1.2.0\n",
        ".github/release-notes/v1.2.0.md": "# 1.2.0\n",
        "docs/usage/releases.md": "## 1.2.0 — 2 November 2026\n",
        "README.md": "pip install opentide==1.2.0\n",
    }
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    (repo / "scripts" / "build").mkdir(parents=True)
    shutil.copy(ROOT / "scripts" / "build" / "release.py", repo / "scripts" / "build")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "notes")
    return repo


def _run_guard(
    repo: Path, *, gh_has_release: bool = False, **env: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to run the workflow step")
    steps = _job("guard")["steps"]
    script = next(step for step in steps if step.get("id") == GUARD_STEP_ID)["run"]
    stubs = repo.parent / "bin"
    stubs.mkdir(exist_ok=True)
    # `gh release view` answers whether the Release exists; `python` is this one.
    (stubs / "gh").write_text(f"#!/bin/sh\nexit {0 if gh_has_release else 1}\n", encoding="utf-8")
    (stubs / "gh").chmod(0o755)
    if not (stubs / "python").exists():
        (stubs / "python").symlink_to(sys.executable)
    output = repo.parent / "github_output"
    output.write_text("", encoding="utf-8")
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=repo,
        env={
            "PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_REPOSITORY": "opentidehq/opentide",
            "GITHUB_REF": "refs/heads/development",
            "GITHUB_REF_NAME": "development",
            "RELEASE_TAG": "development",
            "FROM_BRANCH": "true",
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
    return result, outputs


def test_the_guard_releases_the_version_the_changelog_names(development: Path) -> None:
    result, outputs = _run_guard(development)
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs == {"tag": "v1.2.0", "create_release": "true", "version": "1.2.0"}


def test_the_guard_releases_only_from_development(development: Path) -> None:
    result, outputs = _run_guard(
        development, GITHUB_REF="refs/heads/feature", GITHUB_REF_NAME="feature"
    )
    assert result.returncode == 1
    assert "Run the release from development, not feature" in result.stderr
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


def test_the_guard_still_requires_the_tag_of_a_published_release(development: Path) -> None:
    result, _ = _run_guard(development, FROM_BRANCH="false", RELEASE_TAG="v1.2.0")
    assert result.returncode == 1
    assert "HEAD is not the release tag v1.2.0" in result.stderr
    _git(development, "tag", "v1.2.0")
    result, outputs = _run_guard(development, FROM_BRANCH="false", RELEASE_TAG="v1.2.0")
    assert result.returncode == 0, result.stdout + result.stderr
    assert outputs == {"tag": "v1.2.0", "create_release": "false", "version": "1.2.0"}


def _run_reject(cwd: Path, expected: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to run the workflow step")
    step = _steps()[_step_index(lambda step: step.get("name") == REJECT_STEP)]
    assert step["env"]["EXPECTED_VERSION"] == "${{ needs.guard.outputs.version }}"
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
        "musllinux_1_2_x86_64",
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
    assert "Refusing to publish: no win_arm64 wheel" in result.stdout


def _wheel_steps() -> list[dict[str, Any]]:
    return _job("wheels")["steps"]


def test_wheels_are_built_on_windows_on_arm() -> None:
    assert "windows-11-arm" in _job("wheels")["strategy"]["matrix"]["os"]
    assert "windows-latest" in _job("wheels")["strategy"]["matrix"]["os"]


def test_the_windows_on_arm_wheel_is_installed_and_doctor_runs() -> None:
    """cibuildwheel skips testing it, so the workflow installs it itself (#748)."""
    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover - Python 3.10
        import tomli as tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["tool"]["cibuildwheel"]["test-skip"] == "*-win_arm64"
    names = [step.get("name") for step in _wheel_steps()]
    build = names.index("Build wheels")
    smoke = names.index("Install the win_arm64 wheel and run doctor")
    rust = names.index("Rust on Windows on Arm")
    assert rust < build < smoke
    step = _wheel_steps()[smoke]
    assert step["if"] == "matrix.os == 'windows-11-arm'"
    assert step["env"] == {"PIP_ONLY_BINARY": "cryptography"}
    script = step["run"]
    assert "$PSNativeCommandUseErrorActionPreference = $true" in script
    assert "*-cp310-abi3-win_arm64.whl" in script
    assert "--json doctor --offline" in script
    assert "--json setup --path $workspace --yes" in script
    # Every action stays pinned by commit SHA.
    for job in _workflow()["jobs"].values():
        for item in job.get("steps", []):
            if "uses" in item:
                assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", item["uses"]), item["uses"]
