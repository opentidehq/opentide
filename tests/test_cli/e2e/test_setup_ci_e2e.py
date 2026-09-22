"""CLI E2E: ``opentide setup ci`` writes parseable pipelines (issue #163)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from tests.test_cli.conftest import assert_json_ok

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e

_CI_FILES = (
    ("github", ".github/workflows/opentide.yml"),
    ("gitlab", ".gitlab-ci.yml"),
    ("azure", "azure-pipelines.yml"),
)


@pytest.mark.parametrize(("ci", "relpath"), _CI_FILES)
def test_setup_ci_on_fresh_repo_writes_parseable_yaml(
    invoke_cli, tmp_path: Path, ci: str, relpath: str
) -> None:
    fresh = tmp_path / "fresh-detections"
    run_repo_setup(
        RepoSetupOptions(
            path=fresh,
            name="Fresh",
            yes=True,
            platforms=[DetectionPlatform.sentinel],
        )
    )
    run_platforms_setup(
        PlatformsSetupOptions(path=fresh, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    result = invoke_cli("setup", "ci", ci, "--path", str(fresh), "--yes", repo=fresh)
    payload = assert_json_ok(result)
    assert relpath in payload["files"]
    rendered = (fresh / relpath).read_text(encoding="utf-8")
    parsed = yaml.safe_load(rendered)
    assert parsed is not None
    assert "OPENTIDE_REPO_ROOT" in rendered
    assert "opentide validate" in rendered


def test_setup_ci_default_branch_option_sets_the_trunk(invoke_cli, tmp_path: Path) -> None:
    fresh = tmp_path / "fresh-detections"
    run_repo_setup(RepoSetupOptions(path=fresh, name="Fresh", yes=True))
    result = invoke_cli(
        "setup", "ci", "azure", "--path", str(fresh), "--default-branch", "trunk", "--yes"
    )
    payload = assert_json_ok(result)
    assert payload["default_branch"] == "trunk"
    parsed = yaml.safe_load((fresh / "azure-pipelines.yml").read_text(encoding="utf-8"))
    assert parsed["trigger"]["branches"]["include"] == ["trunk"]
    assert parsed["pr"]["branches"]["include"] == ["trunk"]


@pytest.mark.parametrize("branch", ["main; id", "2024"])
def test_setup_ci_rejects_a_default_branch_it_cannot_render(
    invoke_cli, tmp_path: Path, branch: str
) -> None:
    fresh = tmp_path / "fresh-detections"
    run_repo_setup(RepoSetupOptions(path=fresh, name="Fresh", yes=True))
    result = invoke_cli(
        "setup", "ci", "github", "--path", str(fresh), "--default-branch", branch, "--yes"
    )
    assert result.exit_code == 2, result.stdout + result.stderr
    assert "--default-branch" in result.stderr
    assert not (fresh / ".github" / "workflows" / "opentide.yml").exists()
