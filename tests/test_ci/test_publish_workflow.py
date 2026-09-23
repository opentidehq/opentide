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

    checkout = next(
        step for step in _steps() if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    ref = checkout["with"]["ref"]
    assert "github.event.client_payload.checkout_ref" in ref
    assert "github.event.inputs.checkout_ref" in ref
    assert checkout["with"]["fetch-depth"] == 0


def test_publish_job_does_not_run_scripts_from_the_checkout() -> None:
    # A dispatch retry checks out an older tag; a helper added to scripts/ after
    # that tag would not exist there and the retry would fail.
    offenders = [
        step.get("name", step.get("uses"))
        for step in _steps()
        if "scripts/" in str(step.get("run", ""))
    ]
    assert offenders == []


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
    assert "Expected one wheel and one sdist" in result.stdout
    assert pypi.requests == []
