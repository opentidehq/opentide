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
import threading
import time
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
    tmp_path: Path, tide_corpus_repo: Path, wheel_cache: Path
) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    dist = tmp_path / "dist"
    env_dir = tmp_path / "wheel-venv"
    skills_dest = tmp_path / "skills-repo"
    skills_dest.mkdir()

    wheel = _build_wheel(uv, dist, wheel_cache)

    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    # The binary compiles the data and the schemas in: the wheel carries no copy.
    assert not any(name.startswith(("opentide/data/", "opentide/schemas/")) for name in names)
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


def _build_wheel(uv: str, dist: Path, shared: Path) -> Path:
    """opentide's wheel, with the engine compiled in (maturin), copied into *dist*.

    ``OPENTIDE_TEST_WHEELHOUSE`` names a folder holding one opentide wheel
    already built (CI's build job builds it once for every Python job): that
    wheel is used, and nothing is compiled. Otherwise ``uv build`` builds it,
    with the ``develop`` profile (pyproject.toml's ``[tool.uv]``), which ``uv
    sync`` already compiled, so cargo reuses that build instead of a release one.

    One test run builds the wheel once, in *shared* (``wheel_cache``), under a
    lock its xdist workers share, rather than once per worker.
    """
    wheelhouse = os.environ.get("OPENTIDE_TEST_WHEELHOUSE")
    if wheelhouse:
        built = sorted(Path(wheelhouse).glob("opentide-*.whl"))
        assert len(built) == 1, f"expected one opentide wheel in {wheelhouse}: {built}"
        dist.mkdir(parents=True, exist_ok=True)
        return Path(shutil.copy2(built[0], dist))
    shared.mkdir(exist_ok=True)
    lock = shared / ".lock"
    deadline = time.monotonic() + 1200
    while True:
        try:
            lock.mkdir()
            break
        except FileExistsError:
            if time.monotonic() > deadline:
                pytest.fail(f"another worker held {lock} for 20 minutes")
            time.sleep(1)
    try:
        wheels = list(shared.glob("opentide-*.whl"))
        if not wheels:
            build = _run(
                [uv, "build", "--wheel", "--out-dir", str(shared)],
                cwd=str(ROOT),
                timeout=900,
            )
            assert build.returncode == 0, build.stdout + build.stderr
            wheels = list(shared.glob("opentide-*.whl"))
    finally:
        lock.rmdir()
    assert len(wheels) == 1, f"expected one wheel in {shared}: {wheels}"
    dist.mkdir(parents=True, exist_ok=True)
    return Path(shutil.copy2(wheels[0], dist))


def _install(uv: str, env_dir: Path, spec: str) -> Path:
    """Install *spec*, a wheel that :func:`_build_wheel` wrote."""
    venv = _run([uv, "venv", str(env_dir)], timeout=60)
    assert venv.returncode == 0, venv.stdout + venv.stderr
    python = _venv_bin(env_dir, "python")
    install = _run([uv, "pip", "install", "--python", str(python), spec], timeout=300)
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
    tmp_path: Path, tide_corpus_repo: Path, wheel_cache: Path
) -> None:
    """Issue #526: a BARE install must start the server, with no extra.

    Issue #256/#262: the wheel gate never executed the server, so a start path
    that died with `ModuleNotFoundError: mcp` could ship. Issue #460: that path
    is `opentide mcp start`, and the wheel does not install `opentide-mcp`.

    The server is the Rust one compiled into ``opentide._native`` (UC-6.0c,
    UC-6.2): the wheel no longer depends on the Python ``mcp`` package, and a
    bare install still serves.
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist", wheel_cache)
    env_dir = tmp_path / "bare-venv"
    _install(uv, env_dir, str(wheel))

    removed = _venv_bin(env_dir, "opentide-mcp")
    assert not removed.exists(), "the wheel must not install an opentide-mcp alias"

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
    tmp_path: Path, tide_corpus_repo: Path, wheel_cache: Path
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

    wheel = _build_wheel(uv, tmp_path / "dist", wheel_cache)
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


#: The vendor SDKs and Python packages the Python implementation imported. The
#: Rust core talks to every platform and serves MCP itself (UC-6.2), so a bare
#: ``pip install opentide`` brings none of them.
_REMOVED_DEPENDENCIES = (
    "azure-identity",
    "azure-monitor-query",
    "splunk-sdk",
    "carbon-black-cloud-sdk",
    "mcp",
    "pymisp",
    "typer",
    "rich",
    "textual",
    "questionary",
    "ruamel.yaml",
    "dulwich",
    "structlog",
)


#: What a bare install no longer brings (#747).
_NOT_INSTALLED = ("pandas", "numpy", "openpyxl")


def test_bare_wheel_has_only_the_plugins_extra_and_no_vendor_sdks(
    tmp_path: Path, wheel_cache: Path
) -> None:
    """A bare install, resolved with uv's default pre-release policy, is the slim package.

    uv refuses a transitive pre-release, so a pre-release-only dependency would
    fail this install outright. The wheel declares one extra, `plugins` (pydantic,
    for the plugin API), and none of the Python implementation's dependencies,
    pydantic included, are installed (UC-6.2, #1180).
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist", wheel_cache)
    python = _install(uv, tmp_path / "sdk-venv", str(wheel))

    print_extras = (
        "from importlib.metadata import metadata; "
        "print(metadata('opentide').get_all('Provides-Extra') or [])"
    )
    metadata = _run([str(python), "-c", print_extras], timeout=60)
    assert metadata.stdout.strip() == "['plugins']", metadata.stdout + metadata.stderr
    print_installed = (
        "import importlib.metadata as m; "
        "print(sorted(d.metadata['Name'].lower() for d in m.distributions()))"
    )
    installed = _run([str(python), "-c", print_installed], timeout=60)
    for gone in (*_REMOVED_DEPENDENCIES, *_NOT_INSTALLED, "pydantic"):
        assert f"'{gone}'" not in installed.stdout, installed.stdout + installed.stderr


def test_bare_wheel_installs_the_engine_with_no_extra(tmp_path: Path, wheel_cache: Path) -> None:
    """``pip install opentide`` brings the analysis engine: offline queries and the LSP (#332)."""
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build and install the wheel")

    wheel = _build_wheel(uv, tmp_path / "dist", wheel_cache)
    # One wheel carries the engine, for every CPython from 3.10 on.
    assert "-cp310-abi3-" in wheel.name, wheel.name
    python = _install(uv, tmp_path / "engine-venv", str(wheel))
    probe = _run(
        [
            str(python),
            "-c",
            "; ".join(
                [
                    "import importlib.metadata as m",
                    "from opentide.analysis import check_query, engine_versions",
                    "print(engine_versions())",
                    "found = check_query('SecurityEvent | wher x', language='kql')",
                    "print([f.code for f in found])",
                    "print(sorted(d.metadata['Name'] for d in m.distributions()))",
                ]
            ),
        ],
        timeout=120,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert "kql_unknown_operator" in probe.stdout
    # Nothing besides opentide carries the engine: no second distribution.
    assert "opentide-analysis" not in probe.stdout
    opentide = _venv_bin(tmp_path / "engine-venv", "opentide")
    lsp = _run([str(opentide), "lsp", "start"], input="", timeout=60)
    # The server starts and stops cleanly: stdin closing without `shutdown`
    # is exit 1, as LSP specifies, and stdout carries nothing.
    assert lsp.returncode == 1, lsp.stdout + lsp.stderr
    assert "error:" not in lsp.stderr, lsp.stderr
    assert lsp.stdout == ""


def _assert_json_ok(result: subprocess.CompletedProcess[str]) -> None:
    combined = result.stdout + result.stderr
    assert "UnicodeDecodeError" not in combined
    assert "codec can't decode" not in combined
    assert "FATAL: Agent skills unavailable" not in combined
    assert result.returncode == 0, combined
    payload = json.loads(result.stdout)
    assert payload.get("ok") is True


def test_concurrent_wheel_builds_share_one_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Workers that need the wheel at once build it once, so no two builds race on the checkout."""
    builds: list[list[str]] = []

    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        builds.append(cmd)
        time.sleep(0.2)
        out = Path(cmd[cmd.index("--out-dir") + 1])
        (out / "opentide-0.0.0-py3-none-any.whl").write_bytes(b"wheel")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sys.modules[__name__], "_run", fake_run)
    monkeypatch.delenv("OPENTIDE_TEST_WHEELHOUSE", raising=False)
    shared = tmp_path / "shared"
    found: list[Path] = []
    threads = [
        threading.Thread(
            target=lambda n=n: found.append(_build_wheel("uv", tmp_path / f"d{n}", shared))
        )
        for n in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(builds) == 1
    assert sorted(p.parent.name for p in found) == ["d0", "d1", "d2", "d3"]
    assert all(p.read_bytes() == b"wheel" for p in found)


def test_a_wheelhouse_wheel_is_used_without_building(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CI builds opentide's wheel once (the gate's `build` job): the tests install that one."""

    def no_build(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(f"built a wheel: {cmd}")

    monkeypatch.setattr(sys.modules[__name__], "_run", no_build)
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "opentide-1.0.0-cp310-abi3-linux_x86_64.whl").write_bytes(b"wheel")
    monkeypatch.setenv("OPENTIDE_TEST_WHEELHOUSE", str(wheelhouse))
    wheel = _build_wheel("uv", tmp_path / "dist", tmp_path / "shared")
    assert wheel == tmp_path / "dist" / "opentide-1.0.0-cp310-abi3-linux_x86_64.whl"
    assert wheel.read_bytes() == b"wheel"
