"""Pip-install the built wheel and replay the post-0.1.0 PyPI failures.

Unit tests copy bundled data and compile it in-process. This job builds a real
wheel, installs it into a fresh venv (so pip/compileall write ``__pycache__``
under site-packages), then runs the same commands users hit: ``validate``,
``generate``, and ``setup skills discover`` against the live catalogue.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.cli_e2e

ROOT = Path(__file__).resolve().parents[3]


def _venv_bin(env_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        suffix = "" if name in {"python"} else ".exe"
        candidate = env_dir / "Scripts" / f"{name}{suffix}"
        if name == "python" and not candidate.exists():
            return env_dir / "Scripts" / "python.exe"
        return candidate
    return env_dir / "bin" / name


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        **kwargs,
    )


def test_pip_installed_wheel_validate_generate_and_skills(
    tmp_path: Path, tide_corpus_repo: Path
) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    dist = tmp_path / "dist"
    env_dir = tmp_path / "wheel-venv"
    skills_dest = tmp_path / "skills-repo"
    skills_dest.mkdir()

    build = _run(
        [uv, "build", "--wheel", "--out-dir", str(dist)],
        cwd=str(ROOT),
        timeout=180,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    wheels = list(dist.glob("opentide-*.whl"))
    assert len(wheels) == 1, f"expected one wheel in {dist}: {wheels}"
    wheel = wheels[0]

    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert any(name.endswith("data/configurations/__init__.py") for name in names)
    assert any(name.endswith("data/configurations/platforms/__init__.py") for name in names)
    assert not any(
        "/data/skills/" in name or name.endswith("data/skills/manifest.json") for name in names
    )

    venv = _run([uv, "venv", str(env_dir)], timeout=60)
    assert venv.returncode == 0, venv.stdout + venv.stderr
    python = _venv_bin(env_dir, "python")
    install = _run(
        [uv, "pip", "install", "--python", str(python), str(wheel)],
        timeout=180,
    )
    assert install.returncode == 0, install.stdout + install.stderr

    probe = _run(
        [
            str(python),
            "-c",
            (
                "import compileall, pathlib, opentide; "
                "root = pathlib.Path(opentide.__file__).resolve().parent / 'data' / 'configurations'; "
                "compileall.compile_dir(str(root), quiet=1, force=True); "
                "print(root)"
            ),
        ],
        timeout=60,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    config_dir = Path(probe.stdout.strip())
    assert any(config_dir.rglob("*.pyc")), f"no bytecode under {config_dir}"

    opentide = _venv_bin(env_dir, "opentide")
    assert opentide.is_file(), f"missing console script {opentide}"
    env = {
        **os.environ,
        "OPENTIDE_REPO_ROOT": str(tide_corpus_repo),
        "OPENTIDE_TIDE_WORKSPACE": str(tide_corpus_repo),
        "DEPLOYMENT_PLAN": "FULL",
        "CI": "true",
    }

    validate = _run(
        [str(opentide), "--json", "validate", "--strict"],
        cwd=str(tide_corpus_repo),
        env=env,
        timeout=120,
    )
    _assert_json_ok(validate)
    validate_payload = json.loads(validate.stdout)
    assert validate_payload["report"]["ok"] is True
    assert validate_payload["report"]["stats"]["objects_checked"] > 4

    generate = _run(
        [str(opentide), "--json", "generate", "schemas"],
        cwd=str(tide_corpus_repo),
        env=env,
        timeout=120,
    )
    _assert_json_ok(generate)
    assert (tide_corpus_repo / ".opentide" / "schemas" / "rule.1.0.schema.json").is_file()

    discover = _run(
        [str(opentide), "--json", "setup", "skills", "discover", "--path", str(skills_dest)],
        env=env,
        timeout=60,
    )
    _assert_json_ok(discover)
    discover_payload = json.loads(discover.stdout)
    slugs = {item["slug"] for item in discover_payload["skills"]}
    assert "opentide-detection-rule" in slugs
    assert "detection-engineering" in slugs
    assert discover_payload["manifest_source"] == "remote"
    assert "DEPRECATED" not in discover.stdout + discover.stderr

    install_skills = _run(
        [
            str(opentide),
            "--json",
            "setup",
            "skills",
            "--generic",
            "--yes",
            "--path",
            str(skills_dest),
        ],
        env=env,
        timeout=60,
    )
    _assert_json_ok(install_skills)
    assert (skills_dest / "AGENTS.md").is_file()
    assert (skills_dest / ".agents" / "skills" / "opentide-detection-rule" / "SKILL.md").is_file()
    assert (skills_dest / ".agents" / "skills" / "detection-engineering" / "SKILL.md").is_file()

    info = _run(
        [str(opentide), "--json", "info"],
        cwd=str(tide_corpus_repo),
        env=env,
        timeout=60,
    )
    _assert_json_ok(info)
    info_payload = json.loads(info.stdout)
    platforms = {item["name"]: item for item in info_payload["platforms"]}
    assert platforms["sentinel"]["can_deploy"] is True
    assert platforms["sentinel"]["can_validate"] is True
    assert platforms["splunk"]["can_deploy"] is True
    assert platforms["crowdstrike"]["can_deploy"] is True
    assert platforms["crowdstrike"]["can_validate"] is False
    assert platforms["harfanglab"]["can_validate"] is False

    coverage = _run(
        [str(opentide), "--json", "info", "--technique", "T1059", "coverage"],
        cwd=str(tide_corpus_repo),
        env=env,
        timeout=60,
    )
    _assert_json_ok(coverage)
    coverage_payload = json.loads(coverage.stdout)
    assert coverage_payload["coverage"]["count"] >= 1

    dry_run = _run(
        [
            str(opentide),
            "--json",
            "deploy",
            "--platform",
            "sentinel",
            "--dry-run",
            "--plan",
            "FULL",
            "--wide",
            "--skip-promotion",
        ],
        cwd=str(tide_corpus_repo),
        env=env,
        timeout=120,
    )
    _assert_json_ok(dry_run)
    dry_payload = json.loads(dry_run.stdout)
    assert dry_payload["dry_run"] is True
    assert "Traceback" not in dry_run.stdout + dry_run.stderr
    assert "KeyError" not in dry_run.stdout + dry_run.stderr


def _build_wheel(uv: str, dist: Path) -> Path:
    build = _run([uv, "build", "--wheel", "--out-dir", str(dist)], cwd=str(ROOT), timeout=300)
    assert build.returncode == 0, build.stdout + build.stderr
    wheels = list(dist.glob("opentide-*.whl"))
    assert len(wheels) == 1, f"expected one wheel in {dist}: {wheels}"
    return wheels[0]


def _install(uv: str, env_dir: Path, spec: str) -> Path:
    venv = _run([uv, "venv", str(env_dir)], timeout=60)
    assert venv.returncode == 0, venv.stdout + venv.stderr
    python = _venv_bin(env_dir, "python")
    install = _run([uv, "pip", "install", "--python", str(python), spec], timeout=300)
    assert install.returncode == 0, install.stdout + install.stderr
    return python


def test_bare_wheel_opentide_mcp_reports_the_missing_extra(tmp_path: Path) -> None:
    """Issue #256: `pip install opentide` ships the script; it must explain itself.

    Issue #262: the wheel gate never executed `opentide-mcp`, so a console script
    that died with `ModuleNotFoundError: mcp` shipped twice.
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist")
    python = _install(uv, tmp_path / "bare-venv", str(wheel))

    mcp_script = _venv_bin(tmp_path / "bare-venv", "opentide-mcp")
    assert mcp_script.is_file(), "the base wheel is expected to install opentide-mcp"

    imported = _run([str(python), "-c", "import mcp"], timeout=60)
    if imported.returncode == 0:  # pragma: no cover
        pytest.skip("mcp resolved from the ambient environment; cannot observe a bare install")

    result = _run([str(mcp_script)], timeout=120)
    combined = result.stdout + result.stderr
    assert result.returncode == 1, combined
    assert "ModuleNotFoundError" not in combined
    assert "Traceback" not in combined
    assert "opentide[mcp]" in combined

    # The rest of the CLI must not depend on the extra either.
    cli = _run([str(_venv_bin(tmp_path / "bare-venv", "opentide")), "--help"], timeout=60)
    assert cli.returncode == 0, cli.stdout + cli.stderr


def test_wheel_with_mcp_extra_answers_a_stdio_initialize(
    tmp_path: Path, tide_corpus_repo: Path
) -> None:
    """Issue #262: prove the advertised extra actually starts the server."""
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist")
    env_dir = tmp_path / "mcp-venv"
    _install(uv, env_dir, f"{wheel}[mcp]")

    mcp_script = _venv_bin(env_dir, "opentide-mcp")
    assert mcp_script.is_file()

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "wheel-regression", "version": "0"},
        },
    }
    result = _run(
        [str(mcp_script)],
        input=json.dumps(request) + "\n",
        env={
            **os.environ,
            "OPENTIDE_REPO_ROOT": str(tide_corpus_repo),
            "OPENTIDE_TIDE_WORKSPACE": str(tide_corpus_repo),
            "CI": "true",
        },
        timeout=120,
    )
    combined = result.stdout + result.stderr
    assert "ModuleNotFoundError" not in combined, combined
    response = next(
        (
            payload
            for line in result.stdout.splitlines()
            if line.strip().startswith("{") and (payload := json.loads(line)).get("id") == 1
        ),
        None,
    )
    assert response is not None, f"no JSON-RPC response for initialize:\n{combined}"
    assert response["result"]["serverInfo"]["name"] == "OpenTide"


def _assert_json_ok(result: subprocess.CompletedProcess[str]) -> None:
    combined = result.stdout + result.stderr
    assert "UnicodeDecodeError" not in combined
    assert "codec can't decode" not in combined
    assert "FATAL: Agent skills unavailable" not in combined
    assert result.returncode == 0, combined
    payload = json.loads(result.stdout)
    assert payload.get("ok") is True
