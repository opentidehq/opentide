"""Every workflow builds with the Rust release rust-toolchain.toml pins.

cargo in a checkout runs the toolchain rust-toolchain.toml names, whatever the
runner's default is. A job that installs another one by name (``stable`` from
``dtolnay/rust-toolchain``, say, with the job's targets) leaves the pinned
release without those targets, and its lints differ from the ones the PR was
checked with. The jobs install the file's toolchain, ``rustup toolchain
install`` with no name; only the fuzz workflow names one, nightly, which
cargo-fuzz needs and selects with ``cargo +nightly``. The engine's parked
Release workflow (``.github/engine-workflows/``) is held to the same rule.

An install with no name takes the file's components and targets, and rustup
silently ignores ``--target`` and ``--component`` on it: a job adds a target
with ``rustup target add``, which with no toolchain named adds it to the
pinned release.
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
WORKFLOWS = sorted(
    [
        *(ROOT / ".github" / "workflows").glob("*.yml"),
        *(ROOT / ".github" / "engine-workflows").glob("*.yml"),
    ]
)
# The toolchain-installing actions; none of them reads rust-toolchain.toml.
TOOLCHAIN_ACTIONS = (
    "dtolnay/rust-toolchain",
    "actions-rs/toolchain",
    "actions-rust-lang/setup-rust-toolchain",
)
NAMED = {("engine-fuzz.yml", "nightly")}
# The rustup options that take a value.
VALUED = {"--target", "--component", "--profile", "-t", "-c"}
# The options rustup ignores on a `rustup toolchain install` that names no toolchain.
IGNORED_UNNAMED = re.compile(r"(?:--target|--component)(?:=\S*)?|-[tc]\S*")


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


def _installs(run: str) -> list[str]:
    """The arguments of each ``rustup toolchain install`` in a step's script."""
    return [
        match.group(1).replace("\\\n", " ")
        for match in re.finditer(r"rustup toolchain install((?:[^\n\\]|\\\n)*)", run)
    ]


def _ignored_options(command: str) -> list[str]:
    """The options rustup drops from an install with no toolchain name."""
    if _toolchain_names(command):
        return []
    return [arg for arg in command.split() if IGNORED_UNNAMED.fullmatch(arg)]


def test_the_pin_is_one_release() -> None:
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    assert re.fullmatch(r"\d+\.\d+\.\d+", toolchain["toolchain"]["channel"])


def test_the_workflows_install_rust() -> None:
    names = {path.name for path in WORKFLOWS}
    assert {"ci.yml", "engine-ci.yml", "oracle.yml", "release.yml"} <= names


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_job_installs_the_pinned_release(path: Path) -> None:
    for job_id, step in _steps(path):
        uses = str(step.get("uses", ""))
        assert not uses.startswith(TOOLCHAIN_ACTIONS), (path.name, job_id, uses)
        run = str(step.get("run", ""))
        assert not re.search(r"rustup (?:default|override)", run), (path.name, job_id)
        for command in _installs(run):
            for name in _toolchain_names(command):
                assert (path.name, name) in NAMED, (path.name, job_id, name)
        for name in re.findall(r"cargo \+(\S+)", run):
            assert (path.name, name) in NAMED, (path.name, job_id, name)


def test_a_named_toolchain_is_seen() -> None:
    """The fuzz workflow's nightly install is found: the check above reads the commands."""
    fuzz = ROOT / ".github" / "workflows" / "engine-fuzz.yml"
    found = [
        name
        for _, step in _steps(fuzz)
        for match in re.finditer(r"rustup toolchain install([^\n]*)", str(step.get("run", "")))
        for name in _toolchain_names(match.group(1))
    ]
    assert found == ["nightly"]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_install_passes_an_option_rustup_ignores(path: Path) -> None:
    """``--target`` and ``--component`` on an install with no name install nothing.

    rustup takes the toolchain file's components and targets for it and drops
    these flags without an error, so a job that relies on them builds with no
    std for its target; ``rustup target add`` adds one to the pinned release.
    """
    for job_id, step in _steps(path):
        for command in _installs(str(step.get("run", ""))):
            assert _ignored_options(command) == [], (path.name, job_id, command)


@pytest.mark.parametrize(
    ("run", "ignored"),
    [
        (
            "rustup toolchain install --profile minimal --no-self-update"
            " --target ${{ matrix.target }}",
            ["--target"],
        ),
        (
            "rustup toolchain install --no-self-update \\\n"
            "  --component rustfmt,clippy -t wasm32-wasip1",
            ["--component", "-t"],
        ),
        (
            "rustup toolchain install --target=wasm32-wasip1 -cclippy",
            ["--target=wasm32-wasip1", "-cclippy"],
        ),
        ("rustup toolchain install --profile minimal --no-self-update", []),
        ("rustup toolchain install nightly --profile minimal --component rust-src", []),
    ],
)
def test_an_ignored_option_is_seen(run: str, ignored: list[str]) -> None:
    """The check above reads the flags on an unnamed install, and only there."""
    assert [arg for command in _installs(run) for arg in _ignored_options(command)] == ignored
