"""Tests for setup orchestrator and default callback behaviour."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
import typer

from opentide.cli.enums import CiPlatform, DetectionPlatform, McpHost, SkillTarget
from opentide.cli.services.setup import orchestrator
from opentide.cli.services.setup.orchestrator import SetupOptions, run_setup


def test_run_setup_repo_only(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    result = run_setup(
        SetupOptions(
            path=target,
            name="Test",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
            run_repo=True,
            run_ci=False,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert len(steps) == 1
    assert steps[0]["step"] == "repo"
    assert (target / "README.md").is_file()
    sentinel = target / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    assert sentinel.is_file()
    assert "enabled = true" in sentinel.read_text(encoding="utf-8")


def test_run_setup_with_ci_and_mcp(tmp_path: Path) -> None:
    target = tmp_path / "full"
    result = run_setup(
        SetupOptions(
            path=target,
            name="Test",
            platforms=[DetectionPlatform.sentinel],
            ci=CiPlatform.github,
            mcp_hosts=[McpHost.vscode],
            yes=True,
            run_repo=True,
            run_ci=True,
            run_mcp=True,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert {step["step"] for step in steps} == {"repo", "platforms", "ci", "mcp"}
    assert (target / ".opentide" / "configurations" / "platforms" / "sentinel.toml").is_file()
    workflow = (target / ".github" / "workflows" / "opentide.yml").read_text(encoding="utf-8")
    assert "validate query" in workflow
    assert "sentinel" in workflow
    assert (target / ".vscode" / "mcp.json").is_file()


def test_run_setup_skills_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.test_cli.conftest import stub_remote_skills_manifest

    stub_remote_skills_manifest(monkeypatch)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills._download_skill",
        lambda slug, dest, *, source, ref: (
            dest.mkdir(parents=True, exist_ok=True),
            (dest / "SKILL.md").write_text(f"# {slug}\n", encoding="utf-8"),
            ["SKILL.md"],
        )[2],
    )
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda path, **_: None,
    )
    target = tmp_path / "skills-only"
    target.mkdir()
    result = run_setup(
        SetupOptions(
            path=target,
            skill_targets=[SkillTarget.generic],
            yes=True,
            run_repo=False,
            run_skills=True,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert len(steps) == 1
    assert (target / "AGENTS.md").is_file()


def test_run_setup_soft_fails_optional_skills_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_skills_setup(options: object) -> None:
        raise typer.BadParameter("network unavailable")

    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.run_skills_setup",
        fail_skills_setup,
    )
    result = run_setup(
        SetupOptions(
            path=tmp_path,
            skill_targets=[SkillTarget.generic],
            yes=True,
            run_repo=False,
            run_skills=True,
        )
    )
    assert result["steps"] == []
    assert result["warnings"] == ["Agent skills skipped: network unavailable"]


def test_run_setup_soft_fails_when_skills_manifest_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli.services.setup.skills_registry import SkillsManifestError

    def fail_skills_setup(options: object) -> None:
        raise SkillsManifestError("catalogue unreachable")

    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.run_skills_setup",
        fail_skills_setup,
    )
    result = run_setup(
        SetupOptions(
            path=tmp_path,
            skill_targets=[SkillTarget.generic],
            yes=True,
            run_repo=False,
            run_skills=True,
        )
    )
    assert result["steps"] == []
    assert result["warnings"] == ["Agent skills skipped: catalogue unreachable"]


def test_run_setup_vscode_deprecated(tmp_path: Path) -> None:
    target = tmp_path / "vscode"
    target.mkdir()
    (target / "Schemas" / "Templates").mkdir(parents=True)
    result = run_setup(
        SetupOptions(
            path=target,
            yes=True,
            run_repo=False,
            vscode_setup=True,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert steps[0]["step"] == "vscode"
    assert (target / ".vscode" / "settings.json").is_file()
    vscode_files = steps[0]["files"]
    assert isinstance(vscode_files, list)
    assert ".vscode/settings.json" in vscode_files
    assert ".vscode/extensions.json" in vscode_files
    assert ".vscode/model-templates.code-snippets" in vscode_files
    assert ".vscode/mcp.json" not in vscode_files
    assert not (target / ".vscode" / "mcp.json").exists()


def test_run_setup_vscode_failure_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.orchestrator.run_vscode_setup",
        lambda target: {
            "status": "failed",
            "message": "snippets missing",
            "files": [".vscode/settings.json"],
            "_exit_code": 1,
        },
    )
    result = run_setup(
        SetupOptions(
            path=tmp_path,
            yes=True,
            run_repo=False,
            vscode_setup=True,
        )
    )
    assert result["status"] == "failed"
    assert result["message"] == "snippets missing"
    assert result["_exit_code"] == 1
    assert result["steps"][0]["status"] == "failed"
    assert "_exit_code" not in result["steps"][0]


def test_run_setup_ci_none_skips_ci_step(tmp_path: Path) -> None:
    target = tmp_path / "no-ci"
    result = run_setup(
        SetupOptions(
            path=target,
            name="No CI",
            ci=CiPlatform.none,
            yes=True,
            run_repo=True,
            run_ci=False,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert {step["step"] for step in steps} == {"repo"}


def test_run_setup_auto_platforms_before_ci_without_run_platforms_flag(tmp_path: Path) -> None:
    target = tmp_path / "ci-only"
    result = run_setup(
        SetupOptions(
            path=target,
            platforms=[DetectionPlatform.sentinel],
            ci=CiPlatform.github,
            yes=True,
            run_repo=False,
            run_ci=True,
            run_platforms=False,
        )
    )
    steps = result["steps"]
    assert isinstance(steps, list)
    assert [step["step"] for step in steps] == ["platforms", "ci"]
    workflow = (target / ".github" / "workflows" / "opentide.yml").read_text(encoding="utf-8")
    assert "validate query" in workflow
    assert "sentinel" in workflow


#: The step runners ``run_setup`` calls, found by name so a new step is covered too.
_STEP_RUNNERS = sorted(
    name
    for name, value in vars(orchestrator).items()
    if name.startswith("run_")
    and name.endswith("_setup")
    and getattr(value, "__module__", orchestrator.__name__) != orchestrator.__name__
)


def test_run_setup_lifts_every_step_warning_to_the_top_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#308: human output prints only the top-level ``warnings``, never ``steps[].warnings``."""
    for name in _STEP_RUNNERS:
        monkeypatch.setattr(
            orchestrator,
            name,
            lambda *_, name=name: {"message": name, "warnings": [f"{name} warned"]},
        )

    result = run_setup(
        SetupOptions(
            path=tmp_path,
            platforms=[DetectionPlatform.sentinel],
            ci=CiPlatform.github,
            mcp_hosts=[McpHost.vscode],
            skill_targets=[SkillTarget.generic],
            vscode_setup=True,
            yes=True,
            run_repo=True,
            run_platforms=True,
            run_ci=True,
            run_mcp=True,
            run_skills=True,
        )
    )

    steps = result["steps"]
    assert isinstance(steps, list)
    assert sorted(step["message"] for step in steps) == _STEP_RUNNERS, "a step runner did not run"
    assert all(step["warnings"] == [f"{step['message']} warned"] for step in steps)
    assert result["warnings"] == [f"{step['message']} warned" for step in steps]


def test_run_setup_lists_a_repeated_warning_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator,
        "run_mcp_setup",
        lambda options: {"message": "MCP", "warnings": ["already said", "already said"]},
    )

    result = run_setup(
        SetupOptions(
            path=tmp_path,
            mcp_hosts=[McpHost.vscode],
            yes=True,
            run_repo=False,
            run_mcp=True,
            warnings=["already said"],
        )
    )

    assert result["warnings"] == ["already said"]
    assert result["steps"] == [
        {"step": "mcp", "message": "MCP", "warnings": ["already said", "already said"]}
    ]


def test_run_setup_keeps_step_warnings_in_the_order_they_were_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_skills_setup(options: object) -> None:
        raise typer.BadParameter("network unavailable")

    monkeypatch.setattr(
        orchestrator, "run_mcp_setup", lambda options: {"message": "MCP", "warnings": ["mcp"]}
    )
    monkeypatch.setattr(orchestrator, "run_skills_setup", fail_skills_setup)

    result = run_setup(
        SetupOptions(
            path=tmp_path,
            mcp_hosts=[McpHost.vscode],
            skill_targets=[SkillTarget.generic],
            yes=True,
            run_repo=False,
            run_mcp=True,
            run_skills=True,
            warnings=["wizard"],
        )
    )

    assert result["warnings"] == ["wizard", "mcp", "Agent skills skipped: network unavailable"]


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _repo_on(tmp_path: Path, *branches: str) -> Path:
    """A repository with a commit on each of *branches*, the last one checked out."""
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", branches[0], str(repo))
    _git(repo, "commit", "-q", "--allow-empty", "-m", "seed")
    for branch in branches[1:]:
        _git(repo, "checkout", "-qb", branch)
    return repo


def _detached(repo: Path) -> Path:
    _git(repo, "checkout", "-q", "--detach")
    return repo


def _ci_step(
    repo: Path,
    ci: CiPlatform = CiPlatform.github,
    *,
    platforms: bool = True,
    default_branch: str | None = None,
) -> SetupOptions:
    return SetupOptions(
        path=repo,
        platforms=[DetectionPlatform.sentinel] if platforms else [],
        ci=ci,
        default_branch=default_branch,
        yes=True,
        run_repo=False,
        run_ci=True,
    )


def _mcp_without_its_extra(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SetupOptions:
    monkeypatch.setattr("opentide.mcp_server.launcher.missing_requirements", lambda: ["mcp"])
    return SetupOptions(
        path=tmp_path, mcp_hosts=[McpHost.vscode], yes=True, run_repo=False, run_mcp=True
    )


#: Every condition under which a real step warns: the step, a fragment of its warning, the setup.
_REAL_STEP_WARNINGS: dict[
    str, tuple[str, str, Callable[[Path, pytest.MonkeyPatch], SetupOptions]]
] = {
    "ci-gitlab-ignores-default-branch": (
        "ci",
        "--default-branch is ignored",
        lambda tmp, _: _ci_step(_repo_on(tmp, "trunk"), CiPlatform.gitlab, default_branch="x"),
    ),
    "ci-without-platforms": (
        "ci",
        "No enabled platforms",
        lambda tmp, _: _ci_step(_repo_on(tmp, "trunk"), platforms=False),
    ),
    "ci-fallback-main-is-missing": (
        "ci",
        "'main', which is not a branch",
        lambda tmp, _: _ci_step(_detached(_repo_on(tmp, "trunk"))),
    ),
    "ci-checked-out-branch-is-a-guess": (
        "ci",
        "checked-out branch 'feature'",
        lambda tmp, _: _ci_step(_repo_on(tmp, "main", "feature")),
    ),
    "mcp-extra-missing": ("mcp", "needs opentide[mcp]", _mcp_without_its_extra),
}


@pytest.mark.parametrize(
    ("step_name", "fragment", "scenario"),
    list(_REAL_STEP_WARNINGS.values()),
    ids=list(_REAL_STEP_WARNINGS),
)
def test_run_setup_reports_a_real_step_warning_at_the_top_level(
    tmp_path: Path,
    git_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    step_name: str,
    fragment: str,
    scenario: Callable[[Path, pytest.MonkeyPatch], SetupOptions],
) -> None:
    result = run_setup(scenario(tmp_path, monkeypatch))

    steps = result["steps"]
    assert isinstance(steps, list)
    [step] = [step for step in steps if step["step"] == step_name]
    assert any(fragment in warning for warning in step["warnings"])
    assert result["warnings"] == step["warnings"]
