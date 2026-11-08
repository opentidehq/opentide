"""Every workflow builds with the Rust release rust-toolchain.toml pins.

cargo in a checkout runs the toolchain rust-toolchain.toml names, whatever the
runner's default is. A job that installs another one by name (``stable`` from
``dtolnay/rust-toolchain``, say, with the job's targets) leaves the pinned
release without those targets, and its lints differ from the ones the PR was
checked with. The jobs install the file's toolchain, ``rustup toolchain
install`` with no name; only the fuzz jobs name one, nightly, which
cargo-fuzz needs and selects with ``cargo +nightly`` (the nightly fuzz workflow
and ci.yml's ``fuzz-smoke``). The engine's Release workflows are held to the
same rule.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from opentide.core.files import tomllib

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
# The toolchain-installing actions; none of them reads rust-toolchain.toml.
TOOLCHAIN_ACTIONS = (
    "dtolnay/rust-toolchain",
    "actions-rs/toolchain",
    "actions-rust-lang/setup-rust-toolchain",
)
NAMED = {("engine-fuzz.yml", "nightly"), ("ci.yml", "nightly")}
# The rustup options that take a value.
VALUED = {"--target", "--component", "--profile", "-t", "-c"}


def _steps(path: Path) -> list[tuple[str, dict[str, Any]]]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [
        (job_id, step)
        for job_id, job in (workflow.get("jobs") or {}).items()
        for step in job.get("steps") or []
    ]


def _toolchain_names(command: str) -> list[str]:
    """The toolchains a ``rustup toolchain install`` line names."""
    args = re.sub(r"\$\{\{[^}]*\}\}", "EXPR", command).split()
    return [
        arg
        for before, arg in itertools.pairwise(["--", *args])
        if not arg.startswith("-") and before not in VALUED
    ]


def test_the_pin_is_one_release() -> None:
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    assert re.fullmatch(r"\d+\.\d+\.\d+", toolchain["toolchain"]["channel"])


def test_the_workflows_install_rust() -> None:
    names = {path.name for path in WORKFLOWS}
    assert {
        "ci.yml",
        "oracle.yml",
        "engine-release.yml",
        "engine-release-build.yml",
        "engine-fuzz.yml",
    } <= names


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_job_installs_the_pinned_release(path: Path) -> None:
    for job_id, step in _steps(path):
        uses = str(step.get("uses", ""))
        assert not uses.startswith(TOOLCHAIN_ACTIONS), (path.name, job_id, uses)
        run = str(step.get("run", ""))
        assert not re.search(r"rustup (?:default|override)", run), (path.name, job_id)
        for match in re.finditer(r"rustup toolchain install((?:[^\n\\]|\\\n)*)", run):
            for name in _toolchain_names(match.group(1).replace("\\\n", " ")):
                assert (path.name, name) in NAMED, (path.name, job_id, name)
        for name in re.findall(r"cargo \+(\S+)", run):
            assert (path.name, name) in NAMED, (path.name, job_id, name)


@pytest.mark.parametrize(
    ("workflow", "job"), [("engine-fuzz.yml", "fuzz"), ("ci.yml", "fuzz-smoke")]
)
def test_a_named_toolchain_is_seen(workflow: str, job: str) -> None:
    """The fuzz jobs' nightly install is found: the check above reads the commands."""
    path = ROOT / ".github" / "workflows" / workflow
    found = [
        name
        for job_id, step in _steps(path)
        if job_id == job
        for match in re.finditer(r"rustup toolchain install([^\n]*)", str(step.get("run", "")))
        for name in _toolchain_names(match.group(1))
    ]
    assert found == ["nightly"]


def test_only_the_fuzz_jobs_name_a_toolchain() -> None:
    for path in WORKFLOWS:
        for job_id, step in _steps(path):
            run = str(step.get("run", ""))
            if re.search(r"rustup toolchain install [^\n]*nightly|cargo \+nightly", run):
                assert (path.name, job_id) in {
                    ("engine-fuzz.yml", "fuzz"),
                    ("ci.yml", "fuzz-smoke"),
                }, (path.name, job_id)
