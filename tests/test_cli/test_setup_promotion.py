"""``setup ci`` promotion flags configure the promotion that ``opentide deploy`` runs (#307)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import CiPlatform
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

runner = CliRunner()

OVERRIDE = ".opentide/configurations/deployment.toml"
PIPELINE = ".github/workflows/opentide.yml"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    platforms = repo / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "sentinel.toml").write_text("[platform]\nenabled = true\n", encoding="utf-8")
    return repo


def _setup(repo: Path, **options: Any) -> dict[str, object]:
    return run_ci_setup(CiSetupOptions(path=repo, yes=True, **options))


def _override(repo: Path) -> dict[str, Any]:
    return tomllib.loads((repo / OVERRIDE).read_text(encoding="utf-8"))


@pytest.mark.parametrize("ci", [CiPlatform.github, CiPlatform.gitlab, CiPlatform.azure])
@pytest.mark.parametrize(
    "options", [{}, {"promotion": True, "promotion_target": "PRODUCTION"}], ids=["unset", "given"]
)
def test_default_promotion_writes_no_deployment_override(
    tmp_path: Path, ci: CiPlatform, options: dict[str, object]
) -> None:
    repo = _repo(tmp_path)

    result = _setup(repo, ci=ci, **options)

    assert not (repo / OVERRIDE).exists()
    assert OVERRIDE not in result["files"]  # type: ignore[operator]


@pytest.mark.parametrize(
    ("options", "table"),
    [
        ({"promotion": False}, {"enabled": False}),
        ({"promotion_target": "STAGING"}, {"promotion_target": "STAGING"}),
        (
            {"promotion": False, "promotion_target": "STAGING"},
            {"enabled": False, "promotion_target": "STAGING"},
        ),
    ],
    ids=["no-promotion", "target", "both"],
)
def test_promotion_flags_write_the_keys_that_differ_from_the_defaults(
    tmp_path: Path, options: dict[str, object], table: dict[str, object]
) -> None:
    repo = _repo(tmp_path)

    result = _setup(repo, **options)

    assert _override(repo) == {"promotion": table}
    assert result["files"] == [PIPELINE, OVERRIDE]


def test_an_unknown_promotion_target_is_refused_before_anything_is_written(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)

    with pytest.raises(typer.BadParameter, match="'STAGNG' is not a status"):
        _setup(repo, promotion_target="STAGNG")

    assert not (repo / PIPELINE).exists()
    assert not (repo / OVERRIDE).exists()


def test_the_promotion_target_is_checked_against_the_repository_statuses(
    tmp_path: Path,
) -> None:
    """A client ``[[statuses]]`` list replaces the bundled one, as it does for ``deploy``."""
    repo = _repo(tmp_path)
    statuses = '[[statuses]]\nname = "PILOT"\ndescription = "Pilot"\nstrategy = "PREVIEW"\n'
    (repo / OVERRIDE).write_text(statuses, encoding="utf-8")

    with pytest.raises(typer.BadParameter, match="use one of: PILOT"):
        _setup(repo, promotion_target="STAGING")
    _setup(repo, promotion_target="PILOT")

    assert _override(repo)["promotion"] == {"promotion_target": "PILOT"}


def test_an_existing_override_keeps_its_content(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    existing = (
        "# Proxy for the SOC network\n"
        "[proxy]\n"
        'proxy_host = "proxy.internal"  # outbound only\n'
        "proxy_port = 8080\n"
    )
    (repo / OVERRIDE).write_text(existing, encoding="utf-8")

    _setup(repo, promotion_target="STAGING")

    written = (repo / OVERRIDE).read_text(encoding="utf-8")
    assert written.startswith(existing)
    assert tomllib.loads(written) == {
        **tomllib.loads(existing),
        "promotion": {"promotion_target": "STAGING"},
    }


def test_rerunning_with_the_same_flags_leaves_the_override_alone(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _setup(repo, promotion=False)
    first = (repo / OVERRIDE).read_bytes()

    result = _setup(repo, promotion=False)

    assert (repo / OVERRIDE).read_bytes() == first
    assert result["files"] == [PIPELINE]


@pytest.mark.parametrize(
    "existing",
    ["[promotion]\n# Reviewed by the SOC\nenabled = true\n", "promotion = { enabled = true }\n"],
    ids=["table", "inline"],
)
def test_a_different_promotion_table_is_refused_not_rewritten(
    tmp_path: Path, existing: str
) -> None:
    repo = _repo(tmp_path)
    (repo / OVERRIDE).write_text(existing, encoding="utf-8")

    with pytest.raises(typer.BadParameter, match=r"already has a \[promotion\] table"):
        _setup(repo, promotion=False)

    assert (repo / OVERRIDE).read_text(encoding="utf-8") == existing
    assert not (repo / PIPELINE).exists()


def test_an_override_that_is_not_toml_is_refused(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / OVERRIDE).write_text("[proxy\n", encoding="utf-8")

    with pytest.raises(typer.BadParameter, match="not valid TOML"):
        _setup(repo, promotion=False)

    assert (repo / OVERRIDE).read_text(encoding="utf-8") == "[proxy\n"


def _argv(entry: str) -> list[str]:
    return ["setup", "ci", "github"] if entry == "setup ci" else ["setup", "--ci", "github"]


def _invoke(entry: str, repo: Path, *extra: str, json_output: bool = False) -> Any:
    return runner.invoke(
        app,
        [*(["--json"] if json_output else []), *_argv(entry), "--path", str(repo), *extra, "--yes"],
        env={
            "OPENTIDE_REPO_ROOT": str(repo),
            "OPENTIDE_TIDE_WORKSPACE": str(repo),
            "COLUMNS": "200",
        },
    )


@pytest.mark.parametrize("entry", ["setup ci", "setup --ci"])
def test_both_entry_points_write_the_override(tmp_path: Path, entry: str) -> None:
    repo = _repo(tmp_path)

    result = _invoke(
        entry, repo, "--no-promotion", "--promotion-target", "STAGING", json_output=True
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    if entry == "setup --ci":
        [payload] = [step for step in payload["steps"] if step["step"] == "ci"]
    assert OVERRIDE in payload["files"]
    assert _override(repo) == {"promotion": {"enabled": False, "promotion_target": "STAGING"}}


@pytest.mark.parametrize("entry", ["setup ci", "setup --ci"])
def test_both_entry_points_reject_an_unknown_promotion_target(tmp_path: Path, entry: str) -> None:
    repo = _repo(tmp_path)

    result = _invoke(entry, repo, "--promotion-target", "STAGNG")

    assert result.exit_code == 2, result.stdout + result.stderr
    assert "'STAGNG' is not a status" in re.sub(r"\x1b\[[0-9;]*m|\s+", " ", result.stderr)
    assert sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file()) == [
        ".opentide/configurations/platforms/sentinel.toml"
    ], "setup wrote files"


_PROMOTE = (
    "import sys\n"
    "from pathlib import Path\n"
    "from opentide.mutation.promotion import PromoteMDR\n"
    "PromoteMDR().promote([Path(sys.argv[1])])\n"
)


@pytest.mark.parametrize(
    ("options", "status"),
    [
        ({"promotion_target": "STAGING"}, "STAGING"),
        ({"promotion": False, "promotion_target": "STAGING"}, "DEVELOPMENT"),
    ],
    ids=["target", "no-promotion"],
)
def test_deploy_promotion_follows_what_setup_configured(
    tmp_path: Path, options: dict[str, object], status: str
) -> None:
    repo = _repo(tmp_path)
    _setup(repo, **options)
    rule = repo / "rule.yaml"
    rule.write_text(
        "name: Probe\nconfigurations:\n  sentinel:\n    status: DEVELOPMENT\n", encoding="utf-8"
    )
    env = {
        **os.environ,
        "OPENTIDE_REPO_ROOT": str(repo),
        "OPENTIDE_TIDE_WORKSPACE": str(repo),
        "TERM_PROGRAM": "",
    }
    env.pop("DEBUG", None)

    subprocess.run(
        [sys.executable, "-c", _PROMOTE, str(rule)],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
    )

    assert f"status: {status}\n" in rule.read_text(encoding="utf-8")
