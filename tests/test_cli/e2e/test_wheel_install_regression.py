"""Pip-install the built wheel and replay the post-0.1.0 PyPI failures.

Unit tests copy bundled data and compile it in-process. This job builds a real
wheel, installs it into a fresh venv (so pip/compileall write ``__pycache__``
under site-packages), then runs the same commands users hit: ``validate``,
``generate``, ``setup skills discover``, and offline starter-skill install.
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
    assert any(name.endswith("data/skills/opentide-detection-rule/SKILL.md") for name in names)
    assert any(name.endswith("data/skills/detection-engineering/SKILL.md") for name in names)

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


def _assert_json_ok(result: subprocess.CompletedProcess[str]) -> None:
    combined = result.stdout + result.stderr
    assert "UnicodeDecodeError" not in combined
    assert "codec can't decode" not in combined
    assert "FATAL: Agent skills unavailable" not in combined
    assert result.returncode == 0, combined
    payload = json.loads(result.stdout)
    assert payload.get("ok") is True
