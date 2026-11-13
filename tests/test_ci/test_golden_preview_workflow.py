"""golden-preview.yml: the preview of the next oracle (O1 of the 0.28 catch-up).

While 0.28.1's features are ported on ``train/catchup-0.28``, the committed
recordings stay 0.23.0's. The preview job records every case from the release
``tests/golden/ORACLE.next`` names into a cache, outside ``tests/golden``, and
uploads ``golden check --engine rust --recordings``'s report. It runs only on
the train (its pushes and the pull requests into it), never gates (differences
are expected until each port lands; a check that cannot run fails), and saves
its caches from pushes only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
PREVIEW = WORKFLOWS / "golden-preview.yml"
GUIDE = ROOT / ".github" / "AGENTS.md"
TRAIN = "train/catchup-0.28"
PUSH_ONLY = "github.event_name == 'push'"


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(PREVIEW.read_text(encoding="utf-8"))


def _triggers() -> dict[str, Any]:
    workflow = _workflow()
    # PyYAML reads the key `on` as True.
    return workflow.get("on", workflow.get(True))


def _job() -> dict[str, Any]:
    jobs = _workflow()["jobs"]
    assert list(jobs) == ["preview"]
    return jobs["preview"]


def _steps() -> list[dict[str, Any]]:
    return _job()["steps"]


def _step(name: str) -> dict[str, Any]:
    return next(step for step in _steps() if step.get("name") == name)


def _uses(prefix: str) -> list[dict[str, Any]]:
    return [step for step in _steps() if str(step.get("uses", "")).startswith(prefix)]


def test_it_runs_on_the_train_only() -> None:
    triggers = _triggers()
    assert set(triggers) == {"push", "pull_request", "workflow_dispatch"}
    assert triggers["push"] == {"branches": [TRAIN]}
    assert triggers["pull_request"] == {"branches": [TRAIN]}


def test_it_records_the_preview_oracle_outside_tests_golden() -> None:
    run = _step("Record every case from opentide 0.28.1")["run"]
    assert (
        'cargo xtask golden record --oracle tests/golden/ORACLE.next --out "${PREVIEW_DIR}"' in run
    )
    preview_dir = _job()["env"]["PREVIEW_DIR"]
    assert not preview_dir.startswith(("tests/golden", "target"))
    # A partly recorded preview is still compared; anything worse fails.
    assert "-eq 1 ]]" in run and 'exit "${status}"' in run


def test_the_check_reports_and_never_gates_on_a_difference() -> None:
    run = _step("Compare every command with the preview")["run"]
    assert (
        'cargo xtask golden check --engine rust --recordings "${PREVIEW_DIR}"'
        " --report golden-preview.json" in run
    )
    # Exit status 1 (differences) passes; 2 (could not run) fails.
    assert "-gt 1 ]]" in run
    assert "GITHUB_STEP_SUMMARY" in run
    assert "continue-on-error" not in _job()
    upload = _uses("actions/upload-artifact@")
    assert len(upload) == 1
    assert upload[0]["if"] == "always()"
    assert upload[0]["continue-on-error"] is True
    assert upload[0]["with"]["name"] == "golden-preview"
    assert "golden-preview.json" in upload[0]["with"]["path"]


def test_the_recordings_are_cached_by_their_inputs_and_saved_from_pushes() -> None:
    (restore,) = _uses("actions/cache/restore@")
    (save,) = _uses("actions/cache/save@")
    assert restore["with"]["key"] == save["with"]["key"]
    assert restore["with"]["path"] == save["with"]["path"] == "${{ env.PREVIEW_DIR }}"
    # No restore-keys: older recordings would be another oracle's or other cases'.
    assert "restore-keys" not in restore["with"]
    key = restore["with"]["key"]
    for path in [
        "tests/golden/ORACLE.next",
        "tests/golden/oracle-requirements.next.txt",
        "tests/golden/cases.toml",
        "tests/golden/fixtures/**",
        "tests/fixtures/tide_corpus/**",
        "tests/cassettes/**",
        "xtask/src/golden/**",
    ]:
        assert f"'{path}'" in key, path
    assert str(save["if"]).startswith(PUSH_ONLY)
    assert "cache-hit != 'true'" in str(save["if"])
    record = _step("Record every case from opentide 0.28.1")
    assert record["if"] == "steps.recordings.outputs.cache-hit != 'true'"
    assert not _uses("actions/cache@")
    (rust_cache,) = _uses("Swatinem/rust-cache@")
    assert rust_cache["with"]["save-if"] == "${{ " + PUSH_ONLY + " }}"


def test_it_follows_the_ci_conventions() -> None:
    assert _workflow()["permissions"] == {"contents": "read"}
    assert _job()["env"]["RUSTFLAGS"] == "-Dwarnings"
    (checkout,) = _uses("actions/checkout@")
    assert checkout["with"]["persist-credentials"] is False
    assert any(
        step.get("run") == "rustup toolchain install --profile minimal --no-self-update"
        for step in _steps()
    )
    # The uv that wrote the requirements, as golden.yml's.
    golden = yaml.safe_load((WORKFLOWS / "golden.yml").read_text(encoding="utf-8"))
    golden_uv = next(
        step
        for step in golden["jobs"]["check"]["steps"]
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    )
    (uv,) = _uses("astral-sh/setup-uv@")
    assert uv["with"]["version"] == golden_uv["with"]["version"]


def test_it_is_not_a_required_check() -> None:
    name = _job()["name"]
    guide = GUIDE.read_text(encoding="utf-8")
    for marker in ("required-checks", "required-checks-integration"):
        block = re.search(rf"<!-- {marker} -->\n```text\n(.*?)```", guide, re.DOTALL)
        assert block is not None, marker
        assert name not in block.group(1)
    assert "golden-preview.yml" in guide


def test_the_preview_oracle_names_its_own_requirements() -> None:
    oracle = tomllib.loads((ROOT / "tests" / "golden" / "ORACLE.next").read_text("utf-8"))
    assert oracle["version"] == "0.28.1"
    assert oracle["requirements"] == "oracle-requirements.next.txt"
    requirements = (ROOT / "tests" / "golden" / oracle["requirements"]).read_text("utf-8")
    assert f"opentide=={oracle['version']} \\\n    --hash=sha256:{oracle['wheel_sha256']}\n" in (
        requirements
    )
