"""What the progress, plan, share and setup outcomes count and claim, computed from real inputs."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from opentide.cli.services import deploy_plan
from opentide.cli.services.generation import WrittenFiles, generation_result, generation_step
from opentide.cli.services.share import share_outcome
from opentide.cli.ui import home
from opentide.cli.ui.mode import OutputMode
from opentide.cli.ui.progress import Checklist
from opentide.cli.ui.setup import setup_outcome, shell_quote
from opentide.core.root import get_repo_root
from opentide.models.deployment_enums import StatusStrategy
from opentide.sharing.report import ShareRecord, ShareRun

# --------------------------------------------------------------------------
# Files a generation phase wrote
# --------------------------------------------------------------------------


def _write(path: Path, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_written_files_sees_new_changed_and_removed_files(tmp_path: Path) -> None:
    kept = _write(tmp_path / "kept.txt")
    changed = _write(tmp_path / "changed.txt")
    gone = _write(tmp_path / "gone.txt")
    _write(tmp_path / ".git" / "HEAD")
    watch = WrittenFiles(tmp_path)
    os.utime(changed, ns=(time.time_ns(), changed.stat().st_mtime_ns + 5_000_000_000))
    created = _write(tmp_path / "out" / "new.json")
    _write(tmp_path / ".git" / "index")  # version control is never counted
    gone.unlink()
    written, removed = watch.changes()
    assert written == sorted([changed, created])
    assert removed == [gone]
    assert kept not in written


def test_a_file_from_the_future_is_not_written_by_every_phase(tmp_path: Path) -> None:
    """Clock skew or a checkout from another machine leaves mtimes ahead of the clock."""
    future = _write(tmp_path / "objects" / "rules" / "rule.yaml")
    tomorrow = time.time_ns() + 86_400 * 10**9
    os.utime(future, ns=(tomorrow, tomorrow))
    watch = WrittenFiles(tmp_path)
    snippet = _write(tmp_path / ".vscode" / "model-templates.code-snippets")
    assert watch.changes() == ([snippet], [])


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    get_repo_root.cache_clear()
    yield tmp_path
    get_repo_root.cache_clear()


def test_generation_step_counts_and_locates_what_the_phase_wrote(workspace: Path) -> None:
    tomorrow = time.time_ns() + 86_400 * 10**9
    stale = _write(workspace / "README.md")
    os.utime(stale, ns=(tomorrow, tomorrow))
    with Checklist(mode=OutputMode.JSON) as checklist:
        with generation_step(checklist, "snippets") as step:
            _write(workspace / ".vscode" / "model-templates.code-snippets")
        with generation_step(checklist, "vocabs"):
            pass
    assert (step.count, step.where, step.status) == (1, ".vscode/", "ok")
    assert [s.name for s in checklist.steps] == ["snippets", "vocabularies"]
    assert checklist.steps[1].count == 0 and checklist.steps[1].where is None
    result = generation_result(checklist)
    assert result["message"].startswith("Generated 1 file in ")
    assert result["message"].endswith(" · 2 phases")
    assert result["_summary"]["files"] == 1


def test_generation_step_reports_a_prune_as_removed(workspace: Path) -> None:
    shard = _write(workspace / ".opentide" / "inflight" / "a.json")
    checklist = Checklist(mode=OutputMode.JSON)
    with checklist, generation_step(checklist, "inflight-prune") as step:
        shard.unlink()
    assert (step.name, step.count, step.unit) == ("inflight prune", 1, "file removed")
    assert generation_result(checklist)["message"].startswith("Removed 1 file in ")


def test_a_raising_phase_is_a_failed_step(workspace: Path) -> None:
    checklist = Checklist(mode=OutputMode.JSON)
    with checklist, pytest.raises(RuntimeError), generation_step(checklist, "schemas"):
        raise RuntimeError("boom")
    assert checklist.steps[0].status == "failed"


# --------------------------------------------------------------------------
# Deploy plan: create, update, disable, delete, create or update
# --------------------------------------------------------------------------

DEFENDER = "defender_for_endpoint"
LIVE = "00000000-0000-4000-8000-0000000000a1"
RETIRED = "00000000-0000-4000-8000-0000000000a2"
DELETED = "00000000-0000-4000-8000-0000000000a3"
SENTINEL_RULE = "00000000-0000-4000-8000-0000000000a4"

_STRATEGIES = {
    "PRODUCTION": StatusStrategy.RELEASE,
    "DISABLED": StatusStrategy.DISABLEMENT,
    "REMOVED": StatusStrategy.DELETION,
}


def _rule(name: str, platform: str, status: str) -> SimpleNamespace:
    configurations = SimpleNamespace(**{platform: SimpleNamespace(status=status)})
    return SimpleNamespace(name=name, configurations=configurations)


@pytest.fixture
def catalogue(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from opentide.core import registry
    from opentide.deployment import utils
    from opentide.states.deployment import record_external_id

    rules = {
        LIVE: _rule("Live Rule", DEFENDER, "PRODUCTION"),
        RETIRED: _rule("Retired Rule", DEFENDER, "DISABLED"),
        DELETED: _rule("Deleted Rule", DEFENDER, "REMOVED"),
        SENTINEL_RULE: _rule("Sentinel Rule", "sentinel", "PRODUCTION"),
    }
    monkeypatch.setattr(registry, "Opentide", SimpleNamespace(Rules=rules))
    monkeypatch.setattr(utils, "check_status", lambda status: _STRATEGIES[status])
    # Only the prod tenant has seen LIVE: an id in its shard.
    record_external_id(LIVE, DEFENDER, "prod", "7590", workspace)
    return workspace


def test_plan_reads_create_and_update_from_the_shard_per_tenant(catalogue: Path) -> None:
    changes = deploy_plan.plan_changes(
        {DEFENDER: [LIVE, RETIRED, DELETED], "sentinel": [SENTINEL_RULE]},
        {DEFENDER: {"prod": [LIVE, RETIRED, DELETED], "dev": [LIVE]}},
    )
    actions = {(c.platform, c.tenant, c.name): c.action for c in changes}
    assert actions == {
        (DEFENDER, "prod", "Live Rule"): "update",
        (DEFENDER, "prod", "Retired Rule"): "disable",
        (DEFENDER, "prod", "Deleted Rule"): "delete",
        (DEFENDER, "dev", "Live Rule"): "create",
        ("sentinel", None, "Sentinel Rule"): "upsert",
    }
    assert deploy_plan.plan_message(changes, [DEFENDER, "sentinel"], 2) == (
        "Plan: 1 to create, 1 to update, 1 to create or update, 1 to disable, 1 to delete"
        " · 2 platforms, 2 tenants"
    )


def test_a_state_platform_without_tenants_plans_a_create(catalogue: Path) -> None:
    (change,) = deploy_plan.plan_changes({DEFENDER: [LIVE]}, {})
    assert (change.tenant, change.action, change.status) == (None, "create", "PRODUCTION")


def test_a_platform_outside_deployment_state_is_create_or_update(catalogue: Path) -> None:
    assert deploy_plan._action("sentinel", "prod", SENTINEL_RULE, "PRODUCTION") == "upsert"
    assert deploy_plan._action("sentinel", "prod", SENTINEL_RULE, "DISABLED") == "disable"
    assert deploy_plan._action(DEFENDER, "prod", LIVE, "PRODUCTION") == "update"
    assert deploy_plan._action(DEFENDER, "dev", LIVE, "PRODUCTION") == "create"


# --------------------------------------------------------------------------
# Share outcome
# --------------------------------------------------------------------------


def _run(*actions: str, target: str = "misp-prod") -> ShareRun:
    return ShareRun(
        records=tuple(
            ShareRecord(object_uuid=f"uuid-{index}", target=target, action=action)
            for index, action in enumerate(actions)
        )
    )


@pytest.mark.parametrize(
    ("mode", "actions", "message"),
    [
        (
            "push",
            ("created", "created", "created", "updated"),
            "Shared 4 objects to misp-prod · 3 new, 1 updated",
        ),
        ("push", ("unchanged",) * 5, "Nothing to share · 5 unchanged"),
        (
            "preview",
            ("created", "unchanged"),
            "Would share 1 object to misp-prod · 1 new, 1 unchanged",
        ),
        (
            "retract",
            ("retracted", "failed"),
            "Retracted 1 object from misp-prod · 1 retracted, 1 failed",
        ),
        ("push", ("skipped_tlp", "created"), "Shared 1 object to misp-prod · 1 new, 1 skipped"),
        ("status", ("unchanged", "updated"), "2 objects on misp-prod · 1 updated, 1 unchanged"),
    ],
)
def test_share_outcome_counts_what_was_sent(
    mode: str, actions: tuple[str, ...], message: str
) -> None:
    text, summary = share_outcome(mode, _run(*actions))
    assert text == message
    assert summary["objects"] == sum(
        action in {"created", "updated", "retracted"} for action in actions
    )


# --------------------------------------------------------------------------
# Setup next steps can be pasted
# --------------------------------------------------------------------------


def _scaffold(path: str) -> dict[str, object]:
    return {"path": path, "steps": [{"step": "repo", "name": "My Detections", "scaffolded": True}]}


def test_a_path_with_a_space_is_quoted_in_the_cd_step(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(os, "name", "posix")
    target = tmp_path / "My Detections"
    target.mkdir()
    message, actions = setup_outcome(_scaffold(str(target)))
    assert message == "Created My Detections in ./My Detections"
    assert actions[0].command == "cd 'My Detections'"
    assert (
        subprocess.run(  # noqa: S603 -- the command under test, on a POSIX shell
            ["sh", "-c", f"{actions[0].command} && pwd"], capture_output=True, text=True, check=True
        )
        .stdout.strip()
        .endswith("My Detections")
    )


def test_windows_quoting_and_absolute_windows_paths() -> None:
    assert shell_quote("My Detections", windows=True) == '"My Detections"'
    assert shell_quote("detections", windows=True) == "detections"
    from opentide.cli.ui.setup import _where

    assert _where("C:/Users/you/My Detections/") == "C:/Users/you/My Detections"
    assert _where("/home/you/detections") == "/home/you/detections"
    assert _where("detections/") == "./detections"
    assert _where("../detections") == "../detections"


# --------------------------------------------------------------------------
# Home screen: never claim a clean tree git did not report
# --------------------------------------------------------------------------


def test_git_state_without_status_shows_only_the_branch(monkeypatch, tmp_path: Path) -> None:
    def fake_run(args, **kwargs):
        if "status" in args:
            raise subprocess.TimeoutExpired(args, 2)
        return subprocess.CompletedProcess(args, 0, stdout="main\n", stderr="")

    monkeypatch.setattr(home.subprocess, "run", fake_run)
    assert home._git_state(tmp_path) == "main"


def test_git_state_counts_changes(monkeypatch, tmp_path: Path) -> None:
    def fake_run(args, **kwargs):
        out = " M a\n?? b\n" if "status" in args else "main\n"
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    monkeypatch.setattr(home.subprocess, "run", fake_run)
    assert home._git_state(tmp_path) == "main, 2 changed"


def test_a_long_workspace_path_keeps_its_tail_and_the_git_state() -> None:
    facts = home.HomeFacts(
        version="1",
        workspace=Path("/srv/" + "very-long-directory-name/" * 4 + "detections"),
        git="main, clean",
    )
    line = home.facts_table(facts).plain.splitlines()[0]
    assert line.endswith("detections  git: main, clean")
    assert "…" in line
