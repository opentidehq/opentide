"""CI installs its musl linker and Neovim without Ubuntu's apt mirrors.

On 2026-11-11 GitHub's runners could not reach archive.ubuntu.com or
ports.ubuntu.com, and two steps that ran ``apt-get install`` failed every pull
request: the engine release build's musl linker (engine-release-build.yml,
which ci.yml's dry run and engine-release.yml both call) and the clients job's
Neovim (ci.yml). Each now comes from its upstream release, pinned by version
and sha256: ``scripts/engine/install-musl.sh`` and
``scripts/engine/install-neovim.sh``. These tests hold the workflows to the
scripts, the scripts to their pins, and run each script against a stubbed
``curl``: a download that does not match the pin installs nothing.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
MUSL = ROOT / "scripts" / "engine" / "install-musl.sh"
NEOVIM = ROOT / "scripts" / "engine" / "install-neovim.sh"
SHA256 = re.compile(r"^[0-9a-f]{64}$")

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("sha256sum") is None,
    reason="the install scripts run in bash with coreutils' sha256sum (GitHub's Linux runners)",
)


def _steps(workflow: str, job: str) -> list[dict[str, Any]]:
    data = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    return data["jobs"][job]["steps"]


def _step(workflow: str, job: str, name: str) -> dict[str, Any]:
    matches = [step for step in _steps(workflow, job) if step.get("name") == name]
    assert len(matches) == 1, (workflow, job, name)
    return matches[0]


def _assignment(script: Path, name: str) -> str:
    values = re.findall(rf"^\s*{name}=(\S+)\s*$", script.read_text(encoding="utf-8"), re.MULTILINE)
    assert values, (script.name, name)
    return values[0]


# --- the workflows ----------------------------------------------------------------------


@pytest.mark.parametrize("workflow", ["ci.yml", "engine-release-build.yml"])
def test_no_step_installs_from_ubuntus_archive(workflow: str) -> None:
    data = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    for job_id, job in data["jobs"].items():
        for step in job.get("steps", []):
            run = str(step.get("run", ""))
            assert not re.search(r"\b(apt-get|apt)\s", run), (workflow, job_id, step.get("name"))


def test_the_musl_targets_build_with_the_pinned_musl_gcc() -> None:
    linker = _step("engine-release-build.yml", "native", "musl linker")
    assert linker["if"] == "contains(matrix.target, 'musl')"
    lines = [line.strip() for line in linker["run"].splitlines() if line.strip()]
    assert 'bash scripts/engine/install-musl.sh "$RUNNER_TEMP/musl"' in lines
    assert 'echo "$RUNNER_TEMP/musl/bin" >> "$GITHUB_PATH"' in lines
    assert lines[0] == "set -euo pipefail"
    steps = [step.get("name") for step in _steps("engine-release-build.yml", "native")]
    # Installed before the build, which finds musl-gcc on PATH as the linker and
    # (through the cc crate) as tree-sitter's C compiler.
    assert steps.index("musl linker") < steps.index("build") < steps.index("size budget")
    env = _step("engine-release-build.yml", "native", "build")["env"]
    assert env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"] == "musl-gcc"
    assert env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"] == "musl-gcc"


def test_the_neovim_smoke_test_runs_the_pinned_neovim() -> None:
    step = _step("ci.yml", "clients", "Neovim headless")
    lines = [line.strip() for line in step["run"].splitlines() if line.strip()]
    assert lines == [
        "set -euo pipefail",
        'bash scripts/engine/install-neovim.sh "$RUNNER_TEMP/nvim"',
        '"$RUNNER_TEMP/nvim/bin/nvim" --headless --clean -l scripts/engine/nvim-smoke.lua '
        "target/debug/opentide-lsp",
    ]


# --- the pins ---------------------------------------------------------------------------


def test_musl_is_pinned_to_one_release_and_checksum() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", _assignment(MUSL, "version"))
    assert SHA256.match(_assignment(MUSL, "sha256"))
    text = MUSL.read_text(encoding="utf-8")
    # Upstream first, then Debian's copy of the same tarball: both are checked.
    upstream = text.index('"https://musl.libc.org/releases/musl-${version}.tar.gz"')
    debian = text.index(
        '"https://deb.debian.org/debian/pool/main/m/musl/musl_${version}.orig.tar.gz"'
    )
    assert upstream < debian
    assert "ubuntu.com" not in text


def test_neovim_is_pinned_to_one_release_and_a_checksum_per_architecture() -> None:
    assert re.fullmatch(r"v\d+\.\d+\.\d+", _assignment(NEOVIM, "version"))
    text = NEOVIM.read_text(encoding="utf-8")
    sums = re.findall(r"^\s*sha256=(\S+)\s*$", text, re.MULTILINE)
    assert len(sums) == 2 and len(set(sums)) == 2
    assert all(SHA256.match(value) for value in sums)
    assert (
        "https://github.com/neovim/neovim/releases/download/${version}/nvim-linux-${arch}.tar.gz"
        in text
    )


# --- the scripts, against a stubbed curl ------------------------------------------------

_CURL = """#!/usr/bin/env bash
# Serves $STUB_SERVE for every URL except those containing $STUB_FAIL.
out="" url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    -*) case "$1" in --retry|--connect-timeout|--max-time) shift ;; esac; shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >> "$STUB_LOG"
if [ -n "${STUB_FAIL:-}" ] && [[ "$url" == *"$STUB_FAIL"* ]]; then exit 6; fi
cp "$STUB_SERVE" "$out"
"""


def _tarball(path: Path, files: dict[str, str]) -> str:
    with tarfile.open(path, "w:gz") as archive:
        for name, body in files.items():
            data = body.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(
    script: Path, prefix: Path, tmp_path: Path, serve: Path, fail: str = ""
) -> subprocess.CompletedProcess[str]:
    stubs = tmp_path / "stubs"
    stubs.mkdir(exist_ok=True)
    curl = stubs / "curl"
    curl.write_text(_CURL, encoding="utf-8")
    curl.chmod(0o755)
    # musl's build, stubbed: `make` runs nothing, so `make install` puts no musl-gcc
    # in place; the tarball's own configure writes one.
    make = stubs / "make"
    make.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    make.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "STUB_SERVE": str(serve),
        "STUB_FAIL": fail,
        "STUB_LOG": str(tmp_path / "curl.log"),
    }
    return subprocess.run(
        ["bash", str(script), str(prefix)], capture_output=True, text=True, env=env, check=False
    )


def _repinned(script: Path, tmp_path: Path, sha256: str) -> Path:
    """The script with each sha256 pin replaced (the stub serves a tarball of our own)."""
    text = re.sub(r"(?m)^(\s*sha256=)\S+$", rf"\g<1>{sha256}", script.read_text(encoding="utf-8"))
    copy = tmp_path / script.name
    copy.write_text(text, encoding="utf-8")
    return copy


def _urls(tmp_path: Path) -> list[str]:
    return (tmp_path / "curl.log").read_text(encoding="utf-8").split()


def test_neovim_refuses_a_download_that_does_not_match_the_pin(tmp_path: Path) -> None:
    serve = tmp_path / "served.tar.gz"
    _tarball(serve, {"nvim/bin/nvim": "#!/bin/sh\necho NVIM tampered\n"})
    prefix = tmp_path / "prefix"
    done = _run(NEOVIM, prefix, tmp_path, serve)
    assert done.returncode != 0
    assert not (prefix / "bin" / "nvim").exists()
    (url,) = _urls(tmp_path)
    version = _assignment(NEOVIM, "version")
    assert url.startswith(f"https://github.com/neovim/neovim/releases/download/{version}/")


def test_neovim_installs_a_download_that_matches_the_pin(tmp_path: Path) -> None:
    serve = tmp_path / "served.tar.gz"
    sha = _tarball(serve, {"nvim-linux/bin/nvim": "#!/bin/sh\necho NVIM pinned\n"})
    prefix = tmp_path / "prefix"
    done = _run(_repinned(NEOVIM, tmp_path, sha), prefix, tmp_path, serve)
    assert done.returncode == 0, done.stderr
    assert (prefix / "bin" / "nvim").is_file()
    assert done.stdout.strip().endswith("NVIM pinned")


def test_musl_refuses_downloads_that_do_not_match_the_pin(tmp_path: Path) -> None:
    serve = tmp_path / "served.tar.gz"
    _tarball(serve, {"musl/configure": "#!/bin/sh\nexit 0\n"})
    prefix = tmp_path / "prefix"
    done = _run(MUSL, prefix, tmp_path, serve)
    assert done.returncode != 0
    assert "no source served" in done.stderr
    assert not prefix.exists()
    # Both sources were tried, upstream first.
    upstream, debian = _urls(tmp_path)
    assert upstream.startswith("https://musl.libc.org/")
    assert debian.startswith("https://deb.debian.org/")


def test_musl_falls_back_to_debians_copy_when_upstream_fails(tmp_path: Path) -> None:
    version = _assignment(MUSL, "version")
    serve = tmp_path / "served.tar.gz"
    configure = (
        "#!/bin/sh\n"
        'prefix="${1#--prefix=}"\n'
        'mkdir -p "$prefix/bin"\n'
        "printf '#!/bin/sh\\necho musl-gcc stub\\n' > \"$prefix/bin/musl-gcc\"\n"
        'chmod +x "$prefix/bin/musl-gcc"\n'
    )
    sha = _tarball(serve, {f"musl-{version}/configure": configure})
    prefix = tmp_path / "prefix"
    done = _run(_repinned(MUSL, tmp_path, sha), prefix, tmp_path, serve, fail="musl.libc.org")
    assert done.returncode == 0, done.stderr
    upstream, debian = _urls(tmp_path)
    assert upstream.startswith("https://musl.libc.org/")
    assert debian == (f"https://deb.debian.org/debian/pool/main/m/musl/musl_{version}.orig.tar.gz")
    assert f"musl {version} from {debian}" in done.stdout
    assert done.stdout.strip().endswith("musl-gcc stub")
