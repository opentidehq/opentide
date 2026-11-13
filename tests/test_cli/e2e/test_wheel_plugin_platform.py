"""A platform plugin on opentide installed from its wheel (UC-4.5b, #835).

The editable dev install runs the package from ``src/``; a user's runs from a
wheel, with the engine compiled in by ``hatch_build.py``. This builds that
wheel (``uv build``, as CI's packaging does, the engine on the ``develop``
profile ``uv sync`` already compiled), installs it into a fresh virtual
environment, and beside it the sample plugin ``tests/fixtures/plugin_platform``
as an installer lays it out: its package and a ``.dist-info`` with its
``opentide.platforms`` entry point. The console script of that environment
then plans a deploy on the plugin's platform, runs a query, checks a rule's
query and deploys it against the stand-in Acme tenant on 127.0.0.1, and
``validate`` checks the plugin's blocks (UC-4.5c: with nothing to set).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from tests.corpus_support import materialise_corpus
from tests.test_cli.e2e.test_wheel_install_regression import (
    _build_wheel,
    _install,
    _run,
    _venv_bin,
)
from tests.test_platforms.test_plugin_hook import CASSETTE, FIXTURE, TOKEN, VALID_RULE, StandIn

# A wheel build takes minutes: CI runs this in its full set only (cli-e2e-full).
pytestmark = [pytest.mark.cli_e2e, pytest.mark.full_set]


def _install_plugin(python: Path) -> None:
    """The sample plugin, laid out in *python*'s site-packages as an installer would."""
    found = _run([str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"])
    assert found.returncode == 0, found.stdout + found.stderr
    site = Path(found.stdout.strip())
    shutil.copytree(FIXTURE / "src" / "acme_opentide", site / "acme_opentide")
    info = site / "acme_opentide-0.1.0.dist-info"
    info.mkdir()
    info.joinpath("METADATA").write_text(
        "Metadata-Version: 2.1\nName: acme-opentide\nVersion: 0.1.0\n", encoding="utf-8"
    )
    info.joinpath("entry_points.txt").write_text(
        "[opentide.platforms]\nacme = acme_opentide:AcmePlatform\n", encoding="utf-8"
    )
    info.joinpath("RECORD").write_text("", encoding="utf-8")


def _workspace(root: Path) -> Path:
    repo = materialise_corpus(root)
    shutil.copy(
        FIXTURE / "workspace" / "acme.toml",
        repo / ".opentide" / "configurations" / "platforms" / "acme.toml",
    )
    rules = repo / "Objects" / "Detection Rules"
    for name in ("rule-acme-process.yaml", "rule-acme-invalid.yaml"):
        shutil.copy(FIXTURE / "workspace" / name, rules / name)
    return repo


def test_a_plugin_runs_on_opentide_installed_from_its_wheel(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")
    wheel = _build_wheel(uv, tmp_path / "dist")
    env_dir = tmp_path / "wheel-venv"
    python = _install(uv, env_dir, str(wheel))
    _install_plugin(python)
    repo = _workspace(tmp_path / "workspace")
    opentide = _venv_bin(env_dir, "opentide")

    # The package the console script runs is the wheel's, not the checkout's.
    where = _run([str(python), "-c", "import opentide; print(opentide.__file__)"], cwd=repo)
    assert where.returncode == 0, where.stdout + where.stderr
    assert Path(where.stdout.strip()).resolve().is_relative_to(env_dir.resolve())

    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("OPENTIDE_", "PYTEST_", "VIRTUAL_ENV"))
        and name.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        and name not in ("CI", "GITHUB_ACTIONS", "TF_BUILD", "GITLAB_CI", "PYTHONPATH")
    }
    env.update(
        {
            "OPENTIDE_REPO_ROOT": str(repo),
            "ACME_TOKEN": TOKEN,
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "NO_COLOR": "1",
        }
    )

    with StandIn([]) as tenant:
        env["ACME_URL"] = tenant.url
        planned = _run(
            [
                str(opentide),
                "--json",
                "deploy",
                "--platform",
                "acme",
                "--strategy",
                "PREVIEW",
                "--all",
                "--dry-run",
            ],
            cwd=repo,
            env=env,
            timeout=120,
        )
    assert planned.returncode == 0, planned.stdout + planned.stderr
    plan = json.loads(planned.stdout)
    assert plan["dry_run"] is True
    assert set(plan["plan"]) == {"acme"}
    assert {change["action"] for change in plan["changes"]} == {"create"}
    assert tenant.received == []

    with StandIn(CASSETTE["query"]) as tenant:
        env["ACME_URL"] = tenant.url
        queried = _run(
            [
                str(opentide),
                "--json",
                "query",
                "--platform",
                "acme",
                "--from",
                "2026-11-01T00:00:00Z",
                "--to",
                "2026-11-02T00:00:00Z",
                "--limit",
                "2",
                "process | head",
            ],
            cwd=repo,
            env=env,
            timeout=120,
        )
    assert queried.returncode == 0, queried.stdout + queried.stderr
    assert tenant.received == tenant.requests()
    result = json.loads(queried.stdout)
    assert result["row_count"] == 2
    assert TOKEN not in queried.stdout + queried.stderr

    with StandIn(CASSETTE["validate"]) as tenant:
        env["ACME_URL"] = tenant.url
        checked = _run(
            [
                *(str(opentide), "--json", "validate", "query", "--live"),
                *("--platform", "acme", "--uuid", VALID_RULE),
            ],
            cwd=repo,
            env=env,
            timeout=120,
        )
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert tenant.received == tenant.requests()
    assert json.loads(checked.stdout)["valid"] is True

    with StandIn(CASSETTE["deploy"]) as tenant:
        env["ACME_URL"] = tenant.url
        deployed = _run(
            [
                *(str(opentide), "--json", "deploy", "--platform", "acme"),
                *("--strategy", "PREVIEW", "--uuid", VALID_RULE),
            ],
            cwd=repo,
            env=env,
            timeout=120,
        )
    assert deployed.returncode == 0, deployed.stdout + deployed.stderr
    assert tenant.received == tenant.requests()
    shard = repo / ".opentide" / "states" / "deployment" / f"{VALID_RULE}.json"
    assert json.loads(shard.read_text(encoding="utf-8"))["platforms"] == {
        "acme": {"lab": "acme-rule-17"}
    }

    # validate checks the block with the plugin's model.
    validated = _run([str(opentide), "--json", "validate"], cwd=repo, env=env, timeout=120)
    assert validated.returncode == 1, validated.stdout + validated.stderr
    fields = {
        tuple(issue["field_path"])
        for issue in json.loads(validated.stdout)["report"]["issues"]
        if issue["field_path"][:2] == ["configurations", "acme"]
    }
    assert fields == {
        ("configurations", "acme", "severity"),
        ("configurations", "acme", "colour"),
    }
