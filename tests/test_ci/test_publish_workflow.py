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
    assert triggers["workflow_dispatch"]["inputs"]["checkout_ref"]["required"] is True
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
    assert set(checkouts) == {"guard", "wheels", "sdist"}
    for checkout in checkouts.values():
        ref = checkout["with"]["ref"]
        assert "github.event.client_payload.checkout_ref" in ref
        assert "github.event.inputs.checkout_ref" in ref
    # The guard compares the checkout with the tag, so it needs the tags.
    assert checkouts["guard"]["with"]["fetch-depth"] == 0
    assert workflow["jobs"]["publish"]["needs"] == ["wheels", "sdist"]


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
