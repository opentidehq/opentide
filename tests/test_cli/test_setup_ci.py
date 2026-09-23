"""Tests for setup CI command module."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from structlog.testing import CapturingLogger

from opentide.cli.enums import CiPlatform
from opentide.cli.services.setup import ci as ci_module
from opentide.cli.services.setup.ci import (
    CiSetupOptions,
    detect_default_branch,
    is_valid_branch_name,
    run_ci_setup,
)

_PLATFORM_TOML = "[platform]\nenabled = true\n"


@pytest.mark.parametrize(
    ("ci", "expected"),
    [
        (CiPlatform.github, ".github/workflows/opentide.yml"),
        (CiPlatform.gitlab, ".gitlab-ci.yml"),
        (CiPlatform.azure, "azure-pipelines.yml"),
    ],
)
def test_run_ci_setup(tmp_path: Path, ci: CiPlatform, expected: str) -> None:
    (tmp_path / ".opentide" / "configurations" / "platforms").mkdir(parents=True)
    (tmp_path / ".opentide" / "configurations" / "platforms" / "sentinel.toml").write_text(
        _PLATFORM_TOML, encoding="utf-8"
    )
    result = run_ci_setup(
        CiSetupOptions(
            path=tmp_path,
            ci=ci,
            yes=True,
        )
    )
    assert (tmp_path / expected).is_file()
    assert expected in result["files"]
    assert result["platforms"] == ["sentinel"]
    rendered = (tmp_path / expected).read_text(encoding="utf-8")
    assert "OPENTIDE_REPO_ROOT" in rendered
    parsed = yaml.safe_load(rendered)
    assert parsed is not None


def test_run_ci_setup_skips_none(tmp_path: Path) -> None:
    result = run_ci_setup(CiSetupOptions(path=tmp_path, ci=CiPlatform.none, yes=True))
    assert result["files"] == []
    assert result["message"] == "CI setup skipped"


def test_run_ci_setup_warns_when_no_platforms(tmp_path: Path) -> None:
    result = run_ci_setup(CiSetupOptions(path=tmp_path, ci=CiPlatform.github, yes=True))
    assert result["warnings"]
    assert result["platforms"] == []
    assert "setup platforms" in result["warnings"][0]


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _clone_of_a_trunk(tmp_path: Path, trunk: str) -> Path:
    """A clone whose ``origin/HEAD`` points at *trunk*."""
    upstream = tmp_path / "upstream"
    _git(tmp_path, "init", "-q", "-b", trunk, str(upstream))
    _git(upstream, "commit", "-q", "--allow-empty", "-m", "seed")
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(upstream), str(clone))
    return clone


def test_detect_default_branch_prefers_the_remote_head(tmp_path: Path, git_home: Path) -> None:
    _git(git_home, "config", "--global", "init.defaultBranch", "trunk")
    clone = _clone_of_a_trunk(tmp_path, "development")
    _git(clone, "checkout", "-qb", "feature")
    assert detect_default_branch(clone) == "development"


def test_detect_default_branch_falls_back_to_the_checked_out_branch(
    tmp_path: Path, git_home: Path
) -> None:
    """#288: a ``git init -b trunk`` repository has no remote, and got ``main``."""
    _git(git_home, "config", "--global", "init.defaultBranch", "main")
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", "trunk", str(repo))
    assert detect_default_branch(repo) == "trunk"
    _git(repo, "commit", "-q", "--allow-empty", "-m", "seed")
    assert detect_default_branch(repo / "detections" / "team") == "trunk"


def test_detect_default_branch_falls_back_to_init_default_branch_outside_a_repository(
    tmp_path: Path, git_home: Path
) -> None:
    _git(git_home, "config", "--global", "init.defaultBranch", "trunk")
    assert detect_default_branch(tmp_path / "fresh") == "trunk"


def test_detect_default_branch_skips_a_detached_head(tmp_path: Path, git_home: Path) -> None:
    _git(git_home, "config", "--global", "init.defaultBranch", "trunk")
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", "development", str(repo))
    _git(repo, "commit", "-q", "--allow-empty", "-m", "seed")
    _git(repo, "checkout", "-q", "--detach")
    assert detect_default_branch(repo) == "trunk"


def test_detect_default_branch_falls_back_to_main(tmp_path: Path, git_home: Path) -> None:
    assert detect_default_branch(tmp_path) == "main"


def test_detect_default_branch_reads_a_new_target_from_its_repository(
    tmp_path: Path, git_home: Path
) -> None:
    clone = _clone_of_a_trunk(tmp_path, "master")
    assert detect_default_branch(clone / "detections" / "team") == "master"


def test_detect_default_branch_skips_a_name_it_cannot_render(
    tmp_path: Path, git_home: Path
) -> None:
    _git(git_home, "config", "--global", "init.defaultBranch", "2024")
    assert detect_default_branch(tmp_path) == "main"
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", "2024", str(repo))
    assert detect_default_branch(repo) == "main"


@pytest.mark.parametrize("name", ["main", "master", "development", "release/1.x", "team_a-b.c"])
def test_is_valid_branch_name_accepts(name: str) -> None:
    assert is_valid_branch_name(name)


@pytest.mark.parametrize(
    "name",
    ["", "-x", ".hidden", "a b", "a;b", "$(id)", "it's", "2024", "1.0", "on", "null", "true"],
)
def test_is_valid_branch_name_rejects(name: str) -> None:
    assert not is_valid_branch_name(name)


def _triggers(ci: CiPlatform, parsed: dict[Any, Any]) -> list[str]:
    if ci is CiPlatform.github:
        return parsed[True]["push"]["branches"]
    return parsed["trigger"]["branches"]["include"] + parsed["pr"]["branches"]["include"]


_RENDERED = [
    (CiPlatform.github, ".github/workflows/opentide.yml"),
    (CiPlatform.azure, "azure-pipelines.yml"),
]


@pytest.mark.parametrize(("ci", "relpath"), _RENDERED)
def test_run_ci_setup_renders_the_detected_default_branch(
    tmp_path: Path, git_home: Path, ci: CiPlatform, relpath: str
) -> None:
    clone = _clone_of_a_trunk(tmp_path, "development")

    result = run_ci_setup(CiSetupOptions(path=clone, ci=ci, yes=True))

    assert result["default_branch"] == "development"
    rendered = (clone / relpath).read_text(encoding="utf-8")
    assert set(_triggers(ci, yaml.safe_load(rendered))) == {"development"}
    assert "git fetch origin development" in rendered
    assert "origin main" not in rendered and "refs/heads/main" not in rendered


@pytest.mark.parametrize(("ci", "relpath"), _RENDERED)
def test_run_ci_setup_explicit_default_branch_wins(
    tmp_path: Path, git_home: Path, ci: CiPlatform, relpath: str
) -> None:
    clone = _clone_of_a_trunk(tmp_path, "development")

    result = run_ci_setup(CiSetupOptions(path=clone, ci=ci, default_branch="trunk", yes=True))

    assert result["default_branch"] == "trunk"
    rendered = (clone / relpath).read_text(encoding="utf-8")
    assert set(_triggers(ci, yaml.safe_load(rendered))) == {"trunk"}
    assert "development" not in rendered


def _with_a_platform(repo: Path) -> Path:
    platforms = repo / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "sentinel.toml").write_text(_PLATFORM_TOML, encoding="utf-8")
    return repo


def _repo_on(tmp_path: Path, *branches: str) -> Path:
    """A repository with a commit on each of *branches*, the last one checked out."""
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", branches[0], str(repo))
    _git(repo, "commit", "-q", "--allow-empty", "-m", "seed")
    for branch in branches[1:]:
        _git(repo, "checkout", "-qb", branch)
    return _with_a_platform(repo)


@pytest.fixture
def ci_log(monkeypatch: pytest.MonkeyPatch) -> CapturingLogger:
    captured = CapturingLogger()
    monkeypatch.setattr(ci_module, "logger", captured)
    return captured


def _warning_events(log: CapturingLogger) -> list[tuple[str, object]]:
    return [
        (call.args[0], call.kwargs.get("detail"))
        for call in log.calls
        if call.method_name == "warning"
    ]


def test_run_ci_setup_warns_when_it_falls_back_to_a_main_that_does_not_exist(
    tmp_path: Path, git_home: Path, ci_log: CapturingLogger
) -> None:
    target = _with_a_platform(tmp_path / "fresh")

    result = run_ci_setup(CiSetupOptions(path=target, ci=CiPlatform.github, yes=True))

    assert result["default_branch"] == "main"
    [warning] = result["warnings"]
    assert "'main'" in warning and "--default-branch" in warning
    assert _warning_events(ci_log) == [("ci_default_branch_missing", "main")]


def test_run_ci_setup_keeps_a_fallback_main_that_exists(
    tmp_path: Path, git_home: Path, ci_log: CapturingLogger
) -> None:
    repo = _repo_on(tmp_path, "main")
    _git(repo, "checkout", "-q", "--detach")

    result = run_ci_setup(CiSetupOptions(path=repo, ci=CiPlatform.github, yes=True))

    assert result["default_branch"] == "main"
    assert "warnings" not in result
    assert _warning_events(ci_log) == []


def test_run_ci_setup_warns_when_another_branch_may_deploy(
    tmp_path: Path, git_home: Path, ci_log: CapturingLogger
) -> None:
    """Without origin/HEAD, a feature branch checkout is only a guess at the trunk."""
    repo = _repo_on(tmp_path, "main", "feature")

    result = run_ci_setup(CiSetupOptions(path=repo, ci=CiPlatform.github, yes=True))

    assert result["default_branch"] == "feature"
    [warning] = result["warnings"]
    assert "checked-out branch 'feature'" in warning and "--default-branch" in warning
    assert _warning_events(ci_log) == [("ci_default_branch_guessed", "feature")]


@pytest.mark.parametrize("default_branch", [None, "trunk"])
def test_run_ci_setup_is_quiet_about_a_single_branch_repository(
    tmp_path: Path, git_home: Path, ci_log: CapturingLogger, default_branch: str | None
) -> None:
    repo = _repo_on(tmp_path, "trunk")

    result = run_ci_setup(
        CiSetupOptions(path=repo, ci=CiPlatform.github, default_branch=default_branch, yes=True)
    )

    assert result["default_branch"] == "trunk"
    assert "warnings" not in result
    assert _warning_events(ci_log) == []


def test_run_ci_setup_gitlab_keeps_ci_default_branch(tmp_path: Path, git_home: Path) -> None:
    clone = _clone_of_a_trunk(tmp_path, "development")

    result = run_ci_setup(
        CiSetupOptions(path=clone, ci=CiPlatform.gitlab, default_branch="trunk", yes=True)
    )

    assert result["default_branch"] == "$CI_DEFAULT_BRANCH"
    assert any("--default-branch is ignored" in w for w in result["warnings"])
    rendered = (clone / ".gitlab-ci.yml").read_text(encoding="utf-8")
    assert "trunk" not in rendered and "development" not in rendered


def test_run_ci_setup_rejects_a_branch_it_cannot_render(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Invalid default branch name"):
        run_ci_setup(
            CiSetupOptions(path=tmp_path, ci=CiPlatform.github, default_branch="main; id", yes=True)
        )
    assert not (tmp_path / ".github" / "workflows" / "opentide.yml").exists()
