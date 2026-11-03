"""``opentide setup --plan``, and the wizard's answers as flags on ``setup`` (#751)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from tests.result_models_support import document_problems
from tests.test_cli.conftest import parse_cli_json
from typer.testing import CliRunner

from opentide.cli import app

#: The tutorial's answers (docs/usage/tutorial.md), and every step the wizard offers.
TUTORIAL = [
    "--name",
    "Tutorial Detections",
    "--org",
    "Example Corp",
    "--platform",
    "sentinel",
    "--ci",
    "github",
    "--mcp",
    "vscode",
    "--mcp",
    "claude-code",
    "--skills",
    "generic",
    "--skills",
    "claude-code",
    "--plugin",
    "--hooks",
    "--env",
]


def _tree(root: Path) -> dict[str, tuple[bytes, int]]:
    """Every file under *root*: its bytes and mtime, ``.git/objects`` left out."""
    found: dict[str, tuple[bytes, int]] = {}
    for directory, dirs, files in os.walk(root):
        here = Path(directory)
        if here.name == ".git":
            dirs[:] = [name for name in dirs if name != "objects"]
        for name in files:
            path = here / name
            found[path.relative_to(root).as_posix()] = (path.read_bytes(), path.stat().st_mtime_ns)
    return found


def _changed(before: dict[str, Any], after: dict[str, Any]) -> set[str]:
    return {path for path, value in after.items() if before.get(path) != value}


def _invoke(*args: str) -> Any:
    result = CliRunner().invoke(app, ["--json", "setup", *args])
    return result, parse_cli_json(result)


def _planned(
    document: dict[str, Any], *, actions: tuple[str, ...] = ("create", "merge")
) -> set[str]:
    return {
        item["path"]
        for step in document["steps"]
        for item in step["files"]
        if item["action"] in actions
    }


def _relative(paths: set[str], root: Path, target: Path) -> set[str]:
    """*paths* (relative to *root*) relative to *target*, as the plan shows them."""
    return {Path(os.path.relpath(root / path, target)).as_posix() for path in paths}


@pytest.fixture
def git_repo(tmp_path: Path, git_home: Path) -> Path:
    repo = tmp_path / "work"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    return repo


@pytest.mark.usefixtures("mock_skill_download")
def test_the_plan_writes_nothing_and_lists_what_setup_then_writes(
    git_repo: Path,
) -> None:
    target = git_repo / "tutorial-detections"
    before = _tree(git_repo)

    result, plan = _invoke("--plan", *TUTORIAL, "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    assert document_problems(plan) == []
    assert _tree(git_repo) == before, "setup --plan wrote a file"
    assert not target.exists()
    assert plan["plan"] is True
    assert plan["path"] == str(target.absolute())
    assert plan["message"].endswith("nothing written")
    steps = [step["step"] for step in plan["steps"]]
    assert steps == ["repo", "platforms", "ci", "env", "hooks", "mcp", "skills"]
    for step in plan["steps"]:
        assert set(step) == {"step", "files", "warnings"}
        for item in step["files"]:
            assert set(item) == {"path", "action"}
            assert item["action"] in {"create", "merge", "skip"}
    assert plan["summary"]["create"] == len(
        [item for step in plan["steps"] for item in step["files"] if item["action"] == "create"]
    )

    result, applied = _invoke("--yes", *TUTORIAL, "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    written = _relative(_changed(before, _tree(git_repo)), git_repo, target)
    assert _planned(plan) == written
    assert [step["step"] for step in applied["steps"]] == steps
    # What each step reports writing is what the plan said that step would write.
    for planned_step, applied_step in zip(plan["steps"], applied["steps"], strict=True):
        reported = set(applied_step.get("files") or [])
        planned = {item["path"] for item in planned_step["files"]}
        assert reported <= planned, (applied_step["step"], reported - planned)
    # The git hook sits outside the target, in the repository's .git.
    assert "../.git/hooks/pre-commit" in written
    assert {".vscode/mcp.json", ".mcp.json", ".env.example", ".claude/settings.json"} <= written


@pytest.mark.usefixtures("mock_skill_download")
def test_planning_again_over_a_set_up_repository_merges_and_skips(git_repo: Path) -> None:
    target = git_repo / "detections"
    result, _ = _invoke("--yes", *TUTORIAL, "--path", str(target))
    assert result.exit_code == 0
    before = _tree(git_repo)
    result, plan = _invoke("--plan", *TUTORIAL, "--path", str(target))
    assert result.exit_code == 0
    assert _tree(git_repo) == before
    skipped = _planned(plan, actions=("skip",))
    assert {"README.md", ".gitignore", ".env.example"} <= skipped
    assert not _planned(plan, actions=("create",)) & {"README.md", ".gitignore"}
    result, _ = _invoke("--yes", *TUTORIAL, "--path", str(target))
    written = _relative(_changed(before, _tree(git_repo)), git_repo, target)
    assert _planned(plan) == written


def test_the_plan_of_an_existing_file_is_a_merge(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    (target / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    before = _tree(tmp_path)
    result, plan = _invoke("--plan", "--env", "--path", str(target))
    assert result.exit_code == 0
    assert _tree(tmp_path) == before
    (step,) = plan["steps"]
    assert step["step"] == "env"
    assert {(item["path"], item["action"]) for item in step["files"]} == {
        (".env.example", "create"),
        (".gitignore", "merge"),
    }


@pytest.mark.parametrize(
    ("argv", "step", "expected"),
    [
        (["repo", "--name", "X"], "repo", "README.md"),
        (
            ["platforms", "--sentinel"],
            "platforms",
            ".opentide/configurations/platforms/sentinel.toml",
        ),
        (["ci", "github"], "ci", ".github/workflows/opentide.yml"),
        (["env"], "env", ".env.example"),
        (["hooks"], "hooks", ".pre-commit-config.yaml"),
        (["mcp", "--cursor"], "mcp", ".cursor/mcp.json"),
        (["skills", "--plugin"], "skills", ".claude/settings.json"),
    ],
)
def test_each_subcommand_plans_without_writing(
    tmp_path: Path, argv: list[str], step: str, expected: str
) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    before = _tree(tmp_path)
    result, plan = _invoke(*argv, "--plan", "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    assert _tree(tmp_path) == before
    assert [item["step"] for item in plan["steps"]] == [step]
    assert expected in _planned(plan)
    assert document_problems(plan) == []


def test_plan_given_to_the_group_applies_to_the_subcommand(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    before = _tree(tmp_path)
    result, plan = _invoke("--plan", "--path", str(target), "env")
    assert result.exit_code == 0, result.stdout
    assert _tree(tmp_path) == before
    assert plan["steps"][0]["step"] == "env"


def test_the_plan_needs_the_choices_a_scripted_run_needs(tmp_path: Path) -> None:
    result, document = _invoke("mcp", "--plan", "--path", str(tmp_path))
    assert result.exit_code == 2
    assert document["failure"]["code"] == "usage_missing_option"


def test_a_plan_never_prompts(tmp_path: Path) -> None:
    """`setup --plan` alone is the plan of `setup --yes`: the scaffold, under --json too."""
    result, plan = _invoke("--plan", "--path", str(tmp_path / "new"))
    assert result.exit_code == 0, result.stdout
    assert [step["step"] for step in plan["steps"]] == ["repo"]


def test_new_flags_are_one_non_interactive_command(tmp_path: Path) -> None:
    """--mcp, --hooks and --env answer the wizard's questions; with --yes nothing prompts."""
    target = tmp_path / "repo"
    result, document = _invoke(
        "--yes", "--mcp", "cursor", "--hooks", "--env", "--path", str(target)
    )
    assert result.exit_code == 0, result.stdout
    assert [step["step"] for step in document["steps"]] == ["env", "hooks", "mcp"]
    assert (target / ".cursor" / "mcp.json").is_file()
    assert (target / ".env.example").is_file()
    # Like --ci, these steps leave the scaffold alone unless a repository flag asks for it.
    assert not (target / "README.md").exists()


def test_the_new_flags_without_yes_still_confirm_under_json(tmp_path: Path) -> None:
    result, document = _invoke("--mcp", "cursor", "--path", str(tmp_path))
    assert result.exit_code == 2
    assert document["failure"]["code"] == "usage_needs_input"


def test_an_unknown_host_is_a_usage_error(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["--json", "setup", "--plan", "--mcp", "emacs"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["failure"]["code"].startswith("usage_")


def test_human_plan_lists_each_step_and_file(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app, ["--no-color", "setup", "--plan", "--env", "--path", str(tmp_path / "r")]
    )
    assert result.exit_code == 0, result.stdout
    assert "env" in result.stdout
    assert "create  .env.example" in result.stdout
    assert "nothing written" in result.stdout
    assert not (tmp_path / "r").exists()


# --- what the copy holds ---------------------------------------------------------------


def test_the_plan_never_writes_through_a_link_out_of_the_repository(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    outside = tmp_path / "dotfiles"
    (outside / "vscode").mkdir(parents=True)
    (outside / "mcp.json").write_text('{"mcpServers": {"other": {"command": "x"}}}\n', "utf-8")
    (target / ".mcp.json").symlink_to(outside / "mcp.json")
    (target / ".vscode").symlink_to(outside / "vscode")
    before = _tree(tmp_path)
    result, plan = _invoke("mcp", "--claude-code", "--vscode", "--plan", "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    assert _tree(tmp_path) == before, "the plan wrote through a link"
    assert {".mcp.json", ".vscode/mcp.json"} <= _planned(plan)
    assert plan["summary"]["create"] + plan["summary"]["merge"] >= 2


def test_a_link_inside_the_repository_stays_a_link_in_the_copy(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    (target / "shared").mkdir(parents=True)
    (target / ".vscode").symlink_to(target / "shared")
    before = _tree(tmp_path)
    result, plan = _invoke("mcp", "--vscode", "--plan", "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    assert _tree(tmp_path) == before
    assert "shared/mcp.json" in _planned(plan)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_a_fifo_or_a_socket_in_the_tree_does_not_stop_the_plan(tmp_path: Path) -> None:
    import socket

    target = tmp_path / "repo"
    target.mkdir()
    os.mkfifo(target / "pipe")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = Path.cwd()
    os.chdir(target)  # AF_UNIX paths are short: bind by a relative name
    try:
        server.bind("sock")
    finally:
        os.chdir(previous)
    try:
        result, plan = _invoke("env", "--plan", "--path", str(target))
    finally:
        server.close()
    assert result.exit_code == 0, result.stdout + result.stderr
    assert ".env.example" in _planned(plan)


def test_the_plan_lists_the_files_a_step_removes(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    agents = target / ".agents" / "skills" / "opentide-detection-rule"
    claude = target / ".claude" / "skills" / "opentide-detection-rule"
    for folder in (agents, claude):
        folder.mkdir(parents=True)
        (folder / "SKILL.md").write_text("old\n", encoding="utf-8")
    # A file an older version of the skill shipped: setup replaces opentide's copy whole.
    (agents / "STALE.md").write_text("old\n", encoding="utf-8")
    # The user's own file in the harness copy: setup keeps it.
    (claude / "TEAM-NOTES.md").write_text("ours\n", encoding="utf-8")
    before = _tree(tmp_path)
    result, plan = _invoke("skills", "--claude-code", "--plan", "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    assert _tree(tmp_path) == before
    deleted = _planned(plan, actions=("delete",))
    assert deleted == {".agents/skills/opentide-detection-rule/STALE.md"}
    assert plan["summary"]["delete"] == 1
    assert "1 to remove" in plan["message"]
    assert document_problems(plan) == []

    result, _ = _invoke("skills", "--claude-code", "--yes", "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    assert not (agents / "STALE.md").exists()
    assert (claude / "TEAM-NOTES.md").read_text(encoding="utf-8") == "ours\n"


def test_the_plan_refuses_to_copy_a_home_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("secret\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    result, document = _invoke("env", "--plan", "--path", str(home))
    assert result.exit_code == 2, result.stdout
    assert "home folder" in document["failure"]["message"]


def test_the_plan_refuses_a_tree_too_big_to_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli.services.setup import plan as plan_mod

    target = tmp_path / "repo"
    target.mkdir()
    for number in range(5):
        (target / f"file-{number}.txt").write_text("x", encoding="utf-8")
    monkeypatch.setattr(plan_mod, "MAX_COPY_FILES", 3)
    result, document = _invoke("env", "--plan", "--path", str(target))
    assert result.exit_code == 2, result.stdout
    assert "more than 3 files" in document["failure"]["message"]


def test_the_plan_does_not_copy_build_output(tmp_path: Path) -> None:
    from opentide.cli.services.setup.plan import Sandbox

    target = tmp_path / "repo"
    for folder in ("target", "dist", "build", ".terraform", ".cache", "objects"):
        (target / folder).mkdir(parents=True)
        (target / folder / "x.bin").write_bytes(b"x")
    box = Sandbox(target, tmp_path / "scratch")
    copied = {path.relative_to(box.shadow_top).as_posix() for path in box.shadow_top.rglob("*")}
    assert copied == {"objects", "objects/x.bin"}


def test_sigterm_during_a_plan_removes_the_copy(tmp_path: Path) -> None:
    import signal

    from opentide.cli.services.setup.plan import sandbox

    target = tmp_path / "repo"
    target.mkdir()
    (target / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    copies: list[Path] = []
    with pytest.raises(SystemExit) as stopped, sandbox(target) as box:
        copies.append(box.shadow_top)
        assert (box.shadow_top / ".env").is_file()
        os.kill(os.getpid(), signal.SIGTERM)
    assert stopped.value.code == 128 + signal.SIGTERM
    assert not copies[0].exists()
    assert signal.getsignal(signal.SIGTERM) is not None


def test_the_plan_carries_the_runs_own_warnings(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    args = ("--no-staging", "--lint-changed", "--env", "--path", str(target))
    _, plan = _invoke("--plan", *args)
    _, applied = _invoke("--yes", *args)
    ignored = [w for w in applied["warnings"] if w.startswith("CI flags")]
    assert ignored, applied["warnings"]
    assert ignored[0] in plan["warnings"]


def test_a_skills_download_failure_is_a_step_with_its_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli.services.setup import skills as skills_mod
    from opentide.cli.services.setup.skills_registry import SkillsManifestError

    def unreachable(*args: Any, **kwargs: Any) -> Any:
        raise SkillsManifestError("Could not fetch skills catalogue")

    monkeypatch.setattr(skills_mod, "load_manifest", unreachable)
    target = tmp_path / "repo"
    result, plan = _invoke("--plan", "--hooks", "--skills", "claude-code", "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    assert [step["step"] for step in plan["steps"]] == ["hooks", "skills"]
    skipped = "Agent skills skipped: Could not fetch skills catalogue"
    assert plan["steps"][1]["warnings"] == [skipped]
    assert skipped in plan["warnings"]
    assert document_problems(plan) == []


# --- the plan's .git -------------------------------------------------------------------


def _plan_and_apply(target: Path, *argv: str) -> tuple[dict[str, Any], dict[str, Any]]:
    result, plan = _invoke(*argv, "--plan", "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    result, applied = _invoke(*argv, "--yes", "--path", str(target))
    assert result.exit_code == 0, result.stdout + result.stderr
    return plan, applied


def test_an_absolute_hooks_path_inside_the_repository_is_planned_as_written(
    git_repo: Path,
) -> None:
    subprocess.run(
        ["git", "-C", str(git_repo), "config", "core.hooksPath", str(git_repo / ".githooks")],
        check=True,
    )
    plan, applied = _plan_and_apply(git_repo, "hooks")
    assert ".githooks/pre-commit" in set(applied["files"])
    assert ".githooks/pre-commit" in _planned(plan)
    assert plan.get("warnings", []) == applied.get("warnings", [])
    assert not any("outside this repository" in w for w in plan.get("warnings", []))
