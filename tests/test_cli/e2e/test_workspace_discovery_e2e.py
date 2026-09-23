"""CLI E2E: every command finds the same workspace from anywhere inside it.

Issue #294. Root discovery walked up for ``.git`` only. From ``objects/rules`` in a
scaffold outside git the cwd itself became the root; for a workspace kept below a
larger checkout the checkout did. Either way no objects were found, the enabled
platforms fell back to the bundled defaults, and ``validate --strict`` passed
having checked nothing. These run the installed console script with no
``OPENTIDE_*`` variables, so only the cwd decides where the catalogue is.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
from pytest_console_scripts import RunResult, ScriptRunner
from tests.test_cli.e2e.helpers import write_tutorial_objects

pytestmark = [
    pytest.mark.cli_smoke,
    pytest.mark.script_launch_mode("subprocess"),
]

_LEAKED = (
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "OPENTIDE_DATA_ROOT",
    "DEPLOYMENT_PLAN",
    "CI",
    "GITHUB_ACTIONS",
    "TF_BUILD",
    "INFLIGHT_PATHS",
)

#: ``write_tutorial_objects``: one threat, one objective, one Sentinel rule.
_TUTORIAL_COUNTS = {"rules": 1, "threats": 1, "objectives": 1}


def _env(**overrides: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key not in _LEAKED}
    env.update(overrides)
    return env


def _run(script_runner: ScriptRunner, cwd: Path, args: Sequence[str], **env: str) -> RunResult:
    return script_runner.run(
        ["opentide", "--json", *args], env=_env(**env), cwd=str(cwd), print_result=False
    )


def _ok(result: RunResult) -> dict[str, object]:
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.strip())


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def _scaffold(script_runner: ScriptRunner, workspace: Path) -> Path:
    workspace.parent.mkdir(parents=True, exist_ok=True)
    setup = _run(
        script_runner,
        workspace.parent,
        [
            "setup",
            "--yes",
            "--name",
            "Discovery",
            "--platform",
            "sentinel",
            "--path",
            str(workspace),
        ],
    )
    assert setup.returncode == 0, setup.stdout + setup.stderr
    write_tutorial_objects(workspace)
    return workspace


def _layout(script_runner: ScriptRunner, tmp_path: Path, kind: str) -> tuple[Path, Path]:
    """Return ``(top, workspace)``: where start directories are relative to, and the answer."""
    base = tmp_path.resolve()
    if kind == "standalone":
        workspace = _scaffold(script_runner, base / "scaffold")
        return workspace, workspace
    checkout = base / "monorepo"
    workspace = _scaffold(script_runner, checkout / "detections")
    (checkout / "tools").mkdir()
    _git(checkout, "init", "-q", "-b", "main", ".")
    return checkout, workspace


def _listing(path: Path) -> list[str]:
    return sorted(child.name for child in path.iterdir())


_STARTS = [
    pytest.param("standalone", ".", id="scaffold-root"),
    pytest.param("standalone", "objects/rules", id="scaffold-objects-rules"),
    pytest.param(
        "standalone", ".opentide/configurations/platforms", id="scaffold-platform-configs"
    ),
    pytest.param("nested", "detections", id="nested-workspace-root"),
    pytest.param("nested", "detections/objects/rules", id="nested-objects-rules"),
]


@pytest.mark.parametrize(("kind", "start"), _STARTS)
def test_first_commands_agree_on_the_workspace_wherever_they_start(
    script_runner: ScriptRunner, tmp_path: Path, kind: str, start: str
) -> None:
    top, workspace = _layout(script_runner, tmp_path, kind)
    cwd = top / start
    bystanders = {path: _listing(path) for path in {cwd, top} if path != workspace}

    info = _ok(_run(script_runner, cwd, ["info"]))
    assert Path(info["repo"]) == workspace, info
    assert info["counts"] == _TUTORIAL_COUNTS, info
    assert [p["name"] for p in info["platforms"] if p["enabled"]] == ["sentinel"], info

    validate = _ok(_run(script_runner, cwd, ["validate", "--strict"]))
    assert validate["status"] == "passed", validate
    assert validate["report"]["stats"]["objects_checked"] == 3, validate

    lint = _ok(_run(script_runner, cwd, ["lint", "--strict"]))
    assert Path(lint["path"]) == workspace, lint
    assert lint["count"] == 0, lint

    docs = _ok(_run(script_runner, cwd, ["generate", "docs"]))
    assert Path(docs["output"]) == workspace / "docs", docs
    assert docs["counts"] == _TUTORIAL_COUNTS, docs

    _ok(_run(script_runner, cwd, ["generate"]))
    exported = workspace / ".opentide" / "exports" / "objects.export.json"
    assert len(json.loads(exported.read_text(encoding="utf-8"))) == 3
    assert (workspace / "docs" / "rules" / "sentinel-kql-rule.md").is_file()

    for path, before in bystanders.items():
        assert _listing(path) == before, f"output leaked into {path}"


@pytest.mark.parametrize("start", [".", "tools"])
def test_a_checkout_without_markers_at_its_root_keeps_the_git_root(
    script_runner: ScriptRunner, tmp_path: Path, start: str
) -> None:
    """Above the workspace nothing is marked: the checkout stays the root, as before."""
    checkout, _ = _layout(script_runner, tmp_path, "nested")

    info = _ok(_run(script_runner, checkout / start, ["info"]))
    assert Path(info["repo"]) == checkout, info
    assert info["counts"] == {"rules": 0, "threats": 0, "objectives": 0}, info

    validate = _ok(_run(script_runner, checkout / start, ["validate", "--strict"]))
    assert validate["report"]["stats"]["objects_checked"] == 0, validate


def _threat_only_workspace(script_runner: ScriptRunner, path: Path) -> Path:
    workspace = _scaffold(script_runner, path)
    for family in ("rules", "objectives"):
        for yaml_file in (workspace / "objects" / family).glob("*.yaml"):
            yaml_file.unlink()
    return workspace


@pytest.mark.parametrize(
    "override",
    ["--repo", "OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"],
)
def test_an_explicit_workspace_beats_discovery(
    script_runner: ScriptRunner, tmp_path: Path, override: str
) -> None:
    _, workspace = _layout(script_runner, tmp_path, "nested")
    other = _threat_only_workspace(script_runner, tmp_path.resolve() / "other")
    cwd = workspace / "objects" / "rules"
    flags = ["--repo", str(other)] if override == "--repo" else []
    env = {} if override == "--repo" else {override: str(other)}

    info = _ok(_run(script_runner, cwd, [*flags, "info"], **env))
    assert info["counts"] == {"rules": 0, "threats": 1, "objectives": 0}, info

    validate = _ok(_run(script_runner, cwd, [*flags, "validate", "--strict"], **env))
    assert validate["report"]["stats"]["objects_checked"] == 1, validate
