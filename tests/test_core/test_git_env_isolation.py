"""The suite must never operate on the repository it is testing.

`git` resolves the repository-location `GIT_*` family BEFORE any `cwd` a caller
passes. `git push` exports that family to its hooks, and this project registers
`ci-local-full` as a pre-push hook that runs this suite -- so the git fixtures
once ran against a contributor's own checkout: it was switched to a fixture
branch, a commit deleting 890 files was created, and that commit was published.

`tests/conftest.py` strips the family in an autouse fixture. These tests pin
that it happens, and that a poisoned environment can no longer capture a
fixture repository.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from tests.conftest import _GIT_LOCATION_ENV

pytestmark = pytest.mark.skipif(
    subprocess.run(["git", "--version"], capture_output=True, check=False).returncode != 0,
    reason="git is not available",
)


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.email=t@opentide.test", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return done.stdout.strip()


class TestLocationEnvIsStripped:
    @pytest.mark.parametrize("name", _GIT_LOCATION_ENV)
    def test_the_variable_is_absent_during_a_test(self, name: str) -> None:
        assert name not in os.environ

    def test_the_family_covers_the_ones_git_actually_honours(self) -> None:
        # GIT_DIR and GIT_WORK_TREE are the two that caused the incident; the
        # rest redirect object storage or ref namespacing and are equally able
        # to make a fixture write somewhere unexpected.
        assert "GIT_DIR" in _GIT_LOCATION_ENV
        assert "GIT_WORK_TREE" in _GIT_LOCATION_ENV
        assert "GIT_INDEX_FILE" in _GIT_LOCATION_ENV

    def test_identity_variables_are_left_alone(self) -> None:
        # Tests set these deliberately and they cannot redirect git at another
        # repository, so stripping them would break fixtures for no gain.
        for name in (
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
        ):
            assert name not in _GIT_LOCATION_ENV


class TestPoisonedEnvironmentCannotCaptureAFixture:
    """Reproduces the incident: a decoy repo must come out untouched."""

    def test_a_fixture_repo_is_created_where_cwd_says(self, tmp_path: Path) -> None:
        decoy = tmp_path / "decoy"
        decoy.mkdir()
        _git(decoy, "init", "-q", "-b", "main")
        decoy_head = _git(decoy, "rev-parse", "--absolute-git-dir")

        # What the pre-push hook did to this suite.
        os.environ["GIT_DIR"] = decoy_head
        try:
            fixture = tmp_path / "fixture"
            fixture.mkdir()
            # A helper that sanitises its environment resolves to its own cwd.
            env = {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_ENV}
            subprocess.run(
                ["git", "init", "-q", "-b", "main"],
                cwd=fixture,
                check=True,
                capture_output=True,
                env=env,
            )
            resolved = subprocess.run(
                ["git", "rev-parse", "--absolute-git-dir"],
                cwd=fixture,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            ).stdout.strip()
            assert Path(resolved).resolve() == (fixture / ".git").resolve()
            assert Path(resolved).resolve() != Path(decoy_head).resolve()
        finally:
            os.environ.pop("GIT_DIR", None)

    def test_the_decoy_keeps_its_own_branch_and_no_commits(self, tmp_path: Path) -> None:
        decoy = tmp_path / "decoy"
        decoy.mkdir()
        _git(decoy, "init", "-q", "-b", "main")
        before = _git(decoy, "status", "--porcelain")

        os.environ["GIT_DIR"] = _git(decoy, "rev-parse", "--absolute-git-dir")
        try:
            fixture = tmp_path / "fixture"
            fixture.mkdir()
            env = {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_ENV}
            for args in (
                ["init", "-q", "-b", "main"],
                ["checkout", "-qb", "feature"],
            ):
                subprocess.run(
                    ["git", "-c", "user.email=t@t.test", "-c", "user.name=t", *args],
                    cwd=fixture,
                    check=True,
                    capture_output=True,
                    env=env,
                )
        finally:
            os.environ.pop("GIT_DIR", None)

        # The decoy must not have gained the fixture's branch.
        branches = _git(decoy, "branch", "--list")
        assert "feature" not in branches
        assert _git(decoy, "status", "--porcelain") == before
