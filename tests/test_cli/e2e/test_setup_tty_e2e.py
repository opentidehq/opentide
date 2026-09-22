"""CLI E2E: interactive ``opentide setup`` on a real terminal (issues #255, #260).

The wizard is only reachable when ``sys.stdin.isatty()``, which ``CliRunner``
never satisfies, so ``run_interactive_setup`` had no e2e coverage at all. These
tests spawn the installed console script on a PTY, walk the prompts, and assert
that ``--json`` never mixes Rich output into a document a caller has to parse.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_cli.e2e.pty_driver import (
    ENTER,
    SPACE,
    PtyRun,
    PtySession,
    clean_env,
    requires_pty,
    run_on_pty,
)

pytestmark = pytest.mark.cli_smoke


@pytest.fixture(autouse=True)
def _pty_available() -> None:
    requires_pty()


def _walk_wizard(repo: Path, *, apply: bool) -> PtyRun:
    """Answer every prompt of the full wizard, taking defaults where possible."""
    session = PtySession(
        ["--no-color", "setup", "--path", str(repo)],
        env=clean_env(),
        cwd=repo.parent,
        timeout=180,
    )
    session.expect("Detection Repository Setup")

    session.expect("Repository name")
    session.send(ENTER)
    session.expect("Organisation")
    session.send(ENTER)
    session.expect("Description")
    session.send(ENTER)

    # Checkbox: the first platform is highlighted; space toggles, enter submits.
    session.expect("Detection platforms")
    session.send(SPACE)
    session.send(ENTER)

    session.expect("CI/CD platform")
    session.send(ENTER)  # Configure later

    session.expect("Configure OpenTide MCP")
    session.send(ENTER)  # default No
    session.expect("Install agent skills")
    session.send(ENTER)  # default No

    session.expect("Setup plan")
    session.expect("Apply this setup plan")
    session.send(ENTER if apply else "n" + ENTER)
    return session.finish()


def test_wizard_scaffolds_a_repository(tmp_path: Path) -> None:
    repo = tmp_path / "wizard-detections"
    repo.mkdir(parents=True)

    result = _walk_wizard(repo, apply=True)

    assert result.exit_status == 0, result.clean
    assert (repo / "objects").is_dir(), result.clean
    assert (repo / ".opentide" / "configurations").is_dir(), result.clean


def test_wizard_writes_nothing_when_cancelled(tmp_path: Path) -> None:
    repo = tmp_path / "cancelled-detections"
    repo.mkdir(parents=True)

    result = _walk_wizard(repo, apply=False)

    assert result.exit_status == 0, result.clean
    assert "cancelled" in result.clean.lower(), result.clean
    assert not (repo / "objects").exists(), sorted(p.name for p in repo.iterdir())


def test_json_setup_on_a_tty_emits_one_document(tmp_path: Path) -> None:
    """#255: the wizard used to run first and print JSON after the prompts."""
    repo = tmp_path / "json-detections"
    repo.mkdir(parents=True)

    result = run_on_pty(
        ["--json", "--no-color", "setup", "--path", str(repo)],
        cwd=tmp_path,
    )

    assert result.exit_status != 0, result.clean
    payload = json.loads(result.clean)
    assert payload["ok"] is False
    assert "--json" in payload["message"]
    assert "--yes" in payload["message"]
    assert "Repository name" not in result.clean, result.clean
    assert "Detection Repository Setup" not in result.clean, result.clean
    assert not (repo / "objects").exists()


def test_json_setup_on_a_tty_still_works_when_scripted(tmp_path: Path) -> None:
    """The guard must not break the documented non-interactive invocation."""
    repo = tmp_path / "scripted-detections"

    result = run_on_pty(
        [
            "--json",
            "--no-color",
            "setup",
            "--yes",
            "--platform",
            "sentinel",
            "--path",
            str(repo),
        ],
        cwd=tmp_path,
    )

    assert result.exit_status == 0, result.clean
    payload = json.loads(result.clean)
    assert payload["ok"] is True
    assert (repo / "objects").is_dir()


def test_json_setup_refuses_to_prompt_for_confirmation(tmp_path: Path) -> None:
    """``--json`` without ``--yes`` must not open a Rich confirmation prompt."""
    repo = tmp_path / "confirm-detections"

    result = run_on_pty(
        ["--json", "--no-color", "setup", "--platform", "sentinel", "--path", str(repo)],
        cwd=tmp_path,
    )

    assert result.exit_status != 0, result.clean
    payload = json.loads(result.clean)
    assert payload["ok"] is False
    assert "--yes" in payload["message"]
    assert not repo.exists() or not (repo / "objects").exists()


def test_wizard_without_a_terminal_explains_itself(tmp_path: Path) -> None:
    """Non-TTY stdin has to keep erroring rather than hang on a prompt."""
    import subprocess

    repo = tmp_path / "no-tty-detections"
    result = subprocess.run(
        ["opentide", "--json", "--no-color", "setup", "--path", str(repo)],
        cwd=tmp_path,
        env=clean_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )

    assert result.returncode != 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
