"""Every workflow builds with the Rust release rust-toolchain.toml pins.

cargo in a checkout runs the toolchain rust-toolchain.toml names, whatever the
runner's default is. A job that installs another one by name (``stable`` from
``dtolnay/rust-toolchain``, say, with the job's targets) leaves the pinned
release without those targets, and its lints differ from the ones the PR was
checked with. The jobs install the file's toolchain, ``rustup toolchain
install`` with no name; only the fuzz jobs name one, the dated nightly
``fuzz/NIGHTLY`` pins, which cargo-fuzz needs and selects with ``cargo
+"${FUZZ_TOOLCHAIN}"`` (the nightly fuzz workflow and ci.yml's ``fuzz-smoke``,
a required check that a new nightly must not break unannounced). The engine's
Release workflows are held to the same rule.

An install with no name takes the file's components and targets, and rustup
silently ignores ``--target`` and ``--component`` on it: a job adds a target
with ``rustup target add``, which with no toolchain named adds it to the
pinned release.
"""

from __future__ import annotations

import itertools
import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
# The toolchain-installing actions; none of them reads rust-toolchain.toml.
TOOLCHAIN_ACTIONS = (
    "dtolnay/rust-toolchain",
    "actions-rs/toolchain",
    "actions-rust-lang/setup-rust-toolchain",
)
# The fuzz jobs name the nightly fuzz/NIGHTLY pins, read into FUZZ_TOOLCHAIN.
FUZZ_TOOLCHAIN = '"${FUZZ_TOOLCHAIN}"'
NAMED = {("engine-fuzz.yml", FUZZ_TOOLCHAIN), ("ci.yml", FUZZ_TOOLCHAIN)}
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


# A target: a name, or an expression such as ``${{ matrix.target }}``.
TARGET = r"\$\{\{[^}]*\}\}|\w[\w.-]*"
# The script that builds the WebAssembly engine; a job that runs it builds its targets.
BUILD_WASM = "scripts/engine/build-wasm.sh"


def _lines(script: str) -> list[str]:
    """A shell script's commands, continuation lines joined and comments left out."""
    joined = re.sub(r"\\\n", " ", script)
    return [line for line in joined.splitlines() if not line.lstrip().startswith("#")]


def _targets_added(script: str) -> set[str]:
    """The targets a script's ``rustup target add`` lines add."""
    return {
        name
        for line in _lines(script)
        for listed in re.findall(rf"rustup target add((?: +(?:{TARGET}))+)", line)
        for name in re.findall(TARGET, listed)
    }


def _targets_built(script: str) -> set[str]:
    """The targets a script's cargo commands build for (``--target X``)."""
    built = set()
    for line in _lines(script):
        if re.search(r"\bcargo (?:build|run|clippy|test|check|nextest|package)\b", line):
            built |= set(re.findall(rf"--target[= ]+({TARGET})", line))
        if BUILD_WASM in line:
            built |= _targets_built((ROOT / BUILD_WASM).read_text(encoding="utf-8"))
    return built


def _job_targets(path: Path) -> dict[str, tuple[set[str], set[str]]]:
    """Each job's (built, added) targets."""
    jobs: dict[str, tuple[set[str], set[str]]] = {}
    for job_id, step in _steps(path):
        run = str(step.get("run", ""))
        built, added = jobs.setdefault(job_id, (set(), set()))
        built |= _targets_built(run)
        added |= _targets_added(run)
    return jobs


def test_the_pin_is_one_release() -> None:
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    assert re.fullmatch(r"\d+\.\d+\.\d+", toolchain["toolchain"]["channel"])


def test_the_workflows_install_rust() -> None:
    names = {path.name for path in WORKFLOWS}
    assert {
        "ci.yml",
        "oracle.yml",
        "publish.yml",
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
        for command in _installs(run):
            for name in _toolchain_names(command):
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
    assert found == [FUZZ_TOOLCHAIN]
    run = "\n".join(str(step.get("run", "")) for job_id, step in _steps(path) if job_id == job)
    assert "FUZZ_TOOLCHAIN=$(cat fuzz/NIGHTLY)" in run


def test_the_fuzz_nightly_is_one_dated_release() -> None:
    """One file pins it; the fuzz script reads the same file."""
    pinned = (ROOT / "fuzz" / "NIGHTLY").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", pinned), pinned
    script = (ROOT / "scripts" / "engine" / "fuzz.sh").read_text(encoding="utf-8")
    assert 'toolchain="${FUZZ_TOOLCHAIN:-$(cat "$root/fuzz/NIGHTLY")}"' in script
    assert 'exec cargo "+${toolchain}" fuzz run' in script
    assert "+nightly" not in script


def test_only_the_fuzz_jobs_name_a_toolchain() -> None:
    for path in WORKFLOWS:
        for job_id, step in _steps(path):
            run = str(step.get("run", ""))
            if re.search(
                r"rustup toolchain install [^\n]*(?:nightly|FUZZ_TOOLCHAIN)|cargo \+\S", run
            ):
                assert (path.name, job_id) in {
                    ("engine-fuzz.yml", "fuzz"),
                    ("ci.yml", "fuzz-smoke"),
                }, (path.name, job_id)


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


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_target_a_job_builds_is_added(path: Path) -> None:
    """A job adds each target it builds with ``rustup target add`` in its own steps.

    The unnamed install adds no target, and the runner's default toolchain is not
    the one cargo runs in the checkout. ``build-wasm.sh`` adds its own targets as
    well; the job still states them, so the step that installs Rust is complete.
    """
    for job_id, (built, added) in _job_targets(path).items():
        assert built <= added, (path.name, job_id, sorted(built - added))


def test_the_jobs_that_build_for_a_target_are_seen() -> None:
    """The check above is not empty: it reads the cross builds and build-wasm.sh."""
    wasm = {"wasm32-unknown-unknown", "wasm32-wasip1"}
    found = {
        (path.name, job_id): built
        for path in WORKFLOWS
        for job_id, (built, _) in _job_targets(path).items()
        if built
    }
    assert found[("engine-release-build.yml", "native")] == {"${{ matrix.target }}"}
    assert found[("engine-release-build.yml", "wasm")] == wasm
    assert found[("ci.yml", "engine-wasm")] == wasm


@pytest.mark.parametrize(
    ("script", "added"),
    [
        ("rustup target add ${{ matrix.target }}", {"${{ matrix.target }}"}),
        (
            "rustup target add wasm32-unknown-unknown \\\n  wasm32-wasip1 >/dev/null",
            {"wasm32-unknown-unknown", "wasm32-wasip1"},
        ),
        ("# rustup target add thumbv6m-none-eabi", set()),
        ("rustup toolchain install --target thumbv6m-none-eabi", set()),
    ],
)
def test_an_added_target_is_seen(script: str, added: set[str]) -> None:
    assert _targets_added(script) == added


# A rustup command that installs a toolchain or adds a target or component.
RUSTUP_SETUP = re.compile(r"\brustup +(?:toolchain +install|target +add|component +add)\b")


def _masked_setups(step: dict[str, Any]) -> list[str]:
    """The rustup setup commands in a step whose failure would not fail the step."""
    if not any(RUSTUP_SETUP.search(line) for line in _lines(str(step.get("run", "")))):
        return []
    if step.get("continue-on-error"):
        return ["continue-on-error"]
    return [
        line.strip()
        for line in _lines(str(step.get("run", "")))
        if RUSTUP_SETUP.search(line) and "||" in line
    ]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_a_failed_rustup_setup_fails_the_step(path: Path) -> None:
    """No ``|| true`` (or other ``||``) or ``continue-on-error`` hides a failed install or add.

    A target that was not added only shows up later as a missing std, or not at
    all if the job builds nothing for it in that run.
    """
    for job_id, step in _steps(path):
        assert _masked_setups(step) == [], (path.name, job_id)


@pytest.mark.parametrize(
    ("step", "masked"),
    [
        ({"run": "rustup target add ${{ matrix.target }} || true"}, 1),
        ({"run": "rustup toolchain install --no-self-update \\\n  || echo skipped"}, 1),
        ({"run": "rustup component add rustfmt", "continue-on-error": True}, 1),
        ({"run": "rustup target add wasm32-wasip1\ncargo build || exit 1"}, 0),
        ({"run": "# rustup target add wasm32-wasip1 || true"}, 0),
        ({"run": "cargo build || true", "continue-on-error": True}, 0),
    ],
)
def test_a_masked_rustup_setup_is_seen(step: dict[str, Any], masked: int) -> None:
    assert len(_masked_setups(step)) == masked


def _cibuildwheel_linux() -> dict[str, Any]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["tool"]["cibuildwheel"]["linux"]


def test_the_linux_wheels_build_with_the_pinned_release_minimal() -> None:
    """The manylinux containers install rust-toolchain.toml's release, minimal,
    in before-all, and RUSTUP_TOOLCHAIN names it for the build. Without it,
    rustup read the file in /project and auto-installed the release with its
    components (rustfmt, clippy) mid-build, behind hatch_build.py's quiet
    `rustc -vV`; an install that failed there left a partial toolchain, and
    cargo failed on `clippy-preview ... detected conflict: 'bin/cargo-clippy'`
    (linux-arm64, #1031, #1048)."""
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))[
        "toolchain"
    ]["channel"]
    linux = _cibuildwheel_linux()
    assert linux["environment"]["RUSTUP_TOOLCHAIN"] == channel
    before_all = linux["before-all"]
    assert isinstance(before_all, str)
    installer = before_all.split("|", 1)[1]
    words = installer.split()
    assert words[words.index("--profile") + 1] == "minimal"
    # The release the build runs, installed before it, never `stable`.
    assert words[words.index("--default-toolchain") + 1] == '"$RUSTUP_TOOLCHAIN"'
    assert not re.search(r"(?:-c|--component)\b|clippy|rustfmt", installer), installer


INSTALL_RUST = "scripts/build/install-rust.sh"
BUILD_PACKAGES = ROOT / ".github" / "workflows" / "build-packages.yml"


def _build_packages_jobs() -> dict[str, Any]:
    return yaml.safe_load(BUILD_PACKAGES.read_text(encoding="utf-8"))["jobs"]


def _index(steps: list[dict[str, Any]], name: str) -> int:
    (found,) = [n for n, step in enumerate(steps) if step.get("name") == name]
    return found


@pytest.mark.parametrize(
    ("job_id", "build", "platforms"),
    [
        # Linux wheels build in containers: before-all, above.
        ("wheels", "Build wheels", {"macOS", "Windows"}),
        ("npm-native", "Build the addon", {"Linux", "macOS", "Windows"}),
    ],
)
def test_every_package_build_installs_the_pinned_release_first(
    job_id: str, build: str, platforms: set[str]
) -> None:
    """Each wheel and npm-native build on a runner runs install-rust.sh before
    it builds: the release minimal, named in RUSTUP_TOOLCHAIN. Without it,
    rustup installed rust-toolchain.toml's release mid-build and a macos-arm64
    wheel failed with "'cargo' is not installed for the toolchain" (#1050)."""
    job = _build_packages_jobs()[job_id]
    steps = job["steps"]
    setup = steps[_index(steps, "Set up Rust")]
    assert _index(steps, "Set up Rust") < _index(steps, build), job_id
    assert str(setup["run"]).split()[0] == INSTALL_RUST, setup["run"]
    assert setup.get("shell") == "bash", "Windows runs it with Git Bash"
    condition = str(setup.get("if", ""))
    runners = {"ubuntu": "Linux", "macos": "macOS", "windows": "Windows"}
    systems = {
        next(system for prefix, system in runners.items() if str(cell["os"]).startswith(prefix))
        for cell in job["strategy"]["matrix"]["include"]
    }
    covered = {s for s in systems if not (condition and s == "Linux")}
    assert covered == platforms, (job_id, condition)
    # No other install of Rust in the job: no unnamed install that takes the
    # file's components, no second release.
    for step in steps:
        assert "rustup toolchain install" not in str(step.get("run", "")), (job_id, step)


def test_the_npm_native_build_adds_its_target_through_the_script() -> None:
    steps = _build_packages_jobs()["npm-native"]["steps"]
    assert steps[_index(steps, "Set up Rust")]["run"].strip() == f'{INSTALL_RUST} "${{TARGET}}"'
    assert _build_packages_jobs()["npm-native"]["env"]["TARGET"] == "${{ matrix.target }}"


@pytest.mark.skipif(sys.platform == "win32", reason="runs the script with stub binaries in bash")
def test_the_install_script_installs_the_release_minimal_and_names_it(tmp_path: Path) -> None:
    """install-rust.sh with stub rustup, rustc and cargo: what it asks rustup
    for, and what it leaves in GITHUB_ENV."""
    import os
    import subprocess

    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))[
        "toolchain"
    ]["channel"]
    calls = tmp_path / "calls"
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name in ("rustup", "rustc", "cargo"):
        stub = stubs / name
        stub.write_text(
            f'#!/bin/sh\necho "{name} $* [RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN]" >> "{calls}"\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)
    github_env = tmp_path / "github_env"
    github_env.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_ENV": str(github_env),
    }
    env.pop("RUSTUP_TOOLCHAIN", None)
    subprocess.run(
        ["bash", str(ROOT / INSTALL_RUST), "aarch64-apple-darwin"],
        env=env,
        check=True,
        capture_output=True,
        cwd=tmp_path,
    )
    named = f"[RUSTUP_TOOLCHAIN={channel}]"
    assert calls.read_text(encoding="utf-8").splitlines() == [
        f"rustup toolchain install {channel} --profile minimal --no-self-update {named}",
        f"rustup target add --toolchain {channel} aarch64-apple-darwin {named}",
        f"rustc --version {named}",
        f"cargo --version {named}",
    ]
    assert github_env.read_text(encoding="utf-8") == f"RUSTUP_TOOLCHAIN={channel}\n"
