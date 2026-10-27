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
from tests.test_cli.e2e.helpers import EVERY_RULE

pytestmark = pytest.mark.cli_e2e

ROOT = Path(__file__).resolve().parents[3]


def _venv_bin(env_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        suffix = "" if name == "python" else ".exe"
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

    wheel = _build_wheel(uv, dist)

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
        [uv, "pip", "install", "--python", str(python), "--find-links", str(dist), str(wheel)],
        timeout=180,
    )
    assert install.returncode == 0, install.stdout + install.stderr

    probe = _run(
        [
            str(python),
            "-c",
            (
                "import compileall, pathlib, opentide; "
                "root = pathlib.Path(opentide.__file__).resolve().parent "
                "/ 'data' / 'configurations'; "
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
            *EVERY_RULE,
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
    """opentide's wheel, beside the engine wheel it pins (not on PyPI before a release).

    The engine builds with the ``develop`` profile ``uv sync`` already compiled,
    so it reuses that build instead of a release one.
    """
    build = _run(
        [uv, "build", "--package", "opentide", "--wheel", "--out-dir", str(dist)],
        cwd=str(ROOT),
        timeout=300,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    engine = _run(
        [
            uv,
            "build",
            "--package",
            "opentide-analysis",
            "--wheel",
            "--out-dir",
            str(dist),
            "-C",
            "build-args=--profile develop",
        ],
        cwd=str(ROOT),
        timeout=900,
    )
    assert engine.returncode == 0, engine.stdout + engine.stderr
    assert len(list(dist.glob("opentide_analysis-*.whl"))) == 1
    wheels = list(dist.glob("opentide-*.whl"))
    assert len(wheels) == 1, f"expected one wheel in {dist}: {wheels}"
    return wheels[0]


def _install(uv: str, env_dir: Path, spec: str) -> Path:
    """Install *spec* from a wheel that :func:`_build_wheel` wrote, with its engine wheel."""
    venv = _run([uv, "venv", str(env_dir)], timeout=60)
    assert venv.returncode == 0, venv.stdout + venv.stderr
    python = _venv_bin(env_dir, "python")
    wheel = Path(spec.split("[", 1)[0])
    links = ["--find-links", str(wheel.parent)] if wheel.is_file() else []
    install = _run([uv, "pip", "install", "--python", str(python), *links, spec], timeout=300)
    assert install.returncode == 0, install.stdout + install.stderr
    return python


_INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "wheel-regression", "version": "0"},
    },
}


def _initialize_response(result: subprocess.CompletedProcess[str]) -> dict[str, object] | None:
    """The JSON-RPC reply to :data:`_INITIALIZE_REQUEST`, or ``None``."""
    return next(
        (
            payload
            for line in result.stdout.splitlines()
            if line.strip().startswith("{") and (payload := json.loads(line)).get("id") == 1
        ),
        None,
    )


def test_bare_wheel_mcp_start_answers_a_stdio_initialize(
    tmp_path: Path, tide_corpus_repo: Path
) -> None:
    """Issue #526: a BARE install must start the server, with no extra.

    Issue #256/#262: the wheel gate never executed the server, so a start path
    that died with `ModuleNotFoundError: mcp` could ship. Issue #460: that path
    is `opentide mcp start`, and the wheel does not install `opentide-mcp`.

    This replaces an assertion that a bare install *reports a missing extra*.
    `mcp` became a base dependency in 0.14.0, so that test could only ever skip,
    and the stronger claim -- a bare install actually serves -- went unguarded.
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist")
    env_dir = tmp_path / "bare-venv"
    python = _install(uv, env_dir, str(wheel))

    removed = _venv_bin(env_dir, "opentide-mcp")
    assert not removed.exists(), "the wheel must not install an opentide-mcp alias"

    imported = _run([str(python), "-c", "import mcp.server.mcpserver"], timeout=60)
    assert imported.returncode == 0, (
        "a bare wheel install must ship mcp as a base dependency:\n"
        + imported.stdout
        + imported.stderr
    )

    opentide = _venv_bin(env_dir, "opentide")
    result = _run(
        [str(opentide), "mcp", "start"],
        input=json.dumps(_INITIALIZE_REQUEST) + "\n",
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
    assert "Traceback" not in combined, combined
    assert _initialize_response(result) is not None, (
        f"no JSON-RPC response for initialize:\n{combined}"
    )

    # The rest of the CLI must still work in the same environment.
    cli = _run([str(opentide), "--help"], timeout=60)
    assert cli.returncode == 0, cli.stdout + cli.stderr


def test_wheel_installed_with_a_retired_extra_still_answers_a_stdio_initialize(
    tmp_path: Path, tide_corpus_repo: Path
) -> None:
    """An install command written for an older release still installs a working server.

    Issue #262 proved the ``[mcp]`` extra started the server and #460 made the
    process ``opentide mcp start``. opentide has no extras since 0.16.0: pip and
    uv warn about an extra a package does not declare and install the package
    anyway, so an existing ``opentide[mcp]`` command or editor config keeps
    working without a change.
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist")
    env_dir = tmp_path / "mcp-venv"
    _install(uv, env_dir, f"{wheel}[mcp]")

    opentide = _venv_bin(env_dir, "opentide")
    assert opentide.is_file()
    assert not _venv_bin(env_dir, "opentide-mcp").exists()

    result = _run(
        [str(opentide), "mcp", "start"],
        input=json.dumps(_INITIALIZE_REQUEST) + "\n",
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
    response = _initialize_response(result)
    assert response is not None, f"no JSON-RPC response for initialize:\n{combined}"
    assert response["result"]["serverInfo"]["name"] == "opentide"


#: Every vendor SDK a platform imports. A bare ``pip install opentide`` must
#: carry all of them: there are no extras, and a generated CI pipeline installs
#: exactly ``opentide==<version>`` (the 0.14.2 Sentinel live-validation failure).
_PLATFORM_SDK_IMPORTS = (
    "azure.identity",
    "azure.monitor.query",
    "splunklib.client",
    "cbc_sdk.rest_api",
    "pandas",
    "openpyxl",
)


def test_bare_wheel_imports_every_platform_sdk(tmp_path: Path) -> None:
    """A bare install, resolved with uv's default pre-release policy, has every SDK.

    uv refuses a transitive pre-release, so a pre-release-only dependency (as
    ``azure-mgmt-securityinsight`` is) would fail this install outright.
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist")
    python = _install(uv, tmp_path / "sdk-venv", str(wheel))

    import_every_sdk = "\n".join(
        [
            "import importlib, sys",
            "for name in sys.argv[1:]:",
            "    importlib.import_module(name)",
            "import opentide.platforms.sentinel.client as client",
            "assert client.ALERT_RULES_API_VERSION",
        ]
    )
    probe = _run([str(python), "-c", import_every_sdk, *_PLATFORM_SDK_IMPORTS], timeout=120)
    assert probe.returncode == 0, probe.stdout + probe.stderr
    print_extras = (
        "from importlib.metadata import metadata; "
        "print(metadata('opentide').get_all('Provides-Extra') or [])"
    )
    metadata = _run([str(python), "-c", print_extras], timeout=60)
    assert metadata.stdout.strip() == "[]", metadata.stdout + metadata.stderr


def test_bare_wheel_installs_the_engine_with_no_extra(tmp_path: Path) -> None:
    """``pip install opentide`` brings the analysis engine: offline queries and the LSP (#332)."""
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist")
    python = _install(uv, tmp_path / "engine-venv", str(wheel))
    probe = _run(
        [
            str(python),
            "-c",
            "from opentide.analysis import check_query, engine_versions; "
            "print(engine_versions()); "
            "print([f.code for f in check_query('SecurityEvent | wher x', language='kql')])",
        ],
        timeout=120,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert "kql_unknown_operator" in probe.stdout
    opentide = _venv_bin(tmp_path / "engine-venv", "opentide")
    lsp = _run([str(opentide), "lsp", "start"], input="", timeout=60)
    assert lsp.returncode == 0, lsp.stdout + lsp.stderr
    assert lsp.stdout == ""


def _assert_json_ok(result: subprocess.CompletedProcess[str]) -> None:
    combined = result.stdout + result.stderr
    assert "UnicodeDecodeError" not in combined
    assert "codec can't decode" not in combined
    assert "FATAL: Agent skills unavailable" not in combined
    assert result.returncode == 0, combined
    payload = json.loads(result.stdout)
    assert payload.get("ok") is True
