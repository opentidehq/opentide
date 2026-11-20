"""Every channel of a candidate reports the candidate (RC1-2 of the registries' end-to-end report).

The wheels, the sdist and the GitHub Release's binaries are built from the branch's
workspace, which keeps the release's ``X.Y.Z``; the crates on crates.io are bumped
to ``X.Y.Z-rc.N`` in the publish workflow's checkout. ``opentide-lsp --version``
said ``1.0.0`` from the first three and ``1.0.0-rc.1`` from the crates. The engine and
the language server now report ``opentide_core::VERSION`` (``OPENTIDE_VERSION`` when the
build sets it), and each build that does not take its version from the crates sets it:
the binaries' jobs in their environment, the wheel and the sdist through
``scripts/build/report_version.py``. These tests hold that wiring.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "report_version", ROOT / "scripts" / "build" / "report_version.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _steps(workflow: str, job: str) -> list[dict]:
    jobs = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))["jobs"]
    return jobs[job]["steps"]


@pytest.mark.parametrize(
    ("pypi", "reported"),
    [
        ("1.0.0rc1", "1.0.0-rc.1"),
        ("1.0.0rc12", "1.0.0-rc.12"),
        ("1.0.0", "1.0.0"),
        ("1.0.0.dev7", "1.0.0-dev.7"),
    ],
)
def test_the_reported_version_is_the_wheels_in_semver(pypi: str, reported: str) -> None:
    assert _script().cargo_version(pypi) == reported


def test_a_version_that_is_not_a_wheels_is_refused() -> None:
    with pytest.raises(ValueError, match="not a wheel version"):
        _script().cargo_version("1.0.0-rc.1")


def test_the_config_sets_the_version_and_keeps_what_it_had() -> None:
    script = _script()
    original = '[alias]\nxtask = "run --package xtask --"\n'
    once = script.render(original, "1.0.0-rc.1")
    assert once.startswith(original.rstrip("\n"))
    assert 'OPENTIDE_VERSION = "1.0.0-rc.1"' in once
    # A second run replaces the value; the alias stays.
    twice = script.render(once, "1.0.0-rc.2")
    assert twice.count("OPENTIDE_VERSION") == 1
    assert 'OPENTIDE_VERSION = "1.0.0-rc.2"' in twice
    assert 'xtask = "run --package xtask --"' in twice


def test_the_script_writes_a_config_cargo_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _script()
    monkeypatch.setattr(script, "CONFIG", tmp_path / ".cargo" / "config.toml")
    script.main(["1.0.0rc1"])
    import tomllib

    config = tomllib.loads(script.CONFIG.read_text(encoding="utf-8"))
    assert config["env"] == {"OPENTIDE_VERSION": "1.0.0-rc.1"}


def test_the_wheel_and_the_sdist_builds_set_the_version_they_report() -> None:
    for workflow, job, build in [
        ("build-packages.yml", "wheels", "Build the wheel"),
        ("release-build.yml", "sdist", "Build sdist"),
    ]:
        steps = _steps(workflow, job)
        names = [step.get("name") for step in steps]
        setter = next(
            i for i, step in enumerate(steps) if "report_version.py" in step.get("run", "")
        )
        assert 'report_version.py "${PYPI_VERSION}"' in steps[setter]["run"], workflow
        assert setter < names.index(build), f"{workflow}: set the version before {build}"


def test_the_sdist_carries_the_config_that_sets_it() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'path = "\.cargo/config\.toml", format = "sdist"', pyproject)


def test_the_binaries_are_built_with_the_releases_version() -> None:
    jobs = yaml.safe_load((WORKFLOWS / "engine-release-build.yml").read_text(encoding="utf-8"))[
        "jobs"
    ]
    native = jobs["native"]
    # SemVer, the tag without its v (`1.0.0-rc.1`), for both cargo builds.
    assert native["env"]["OPENTIDE_VERSION"] == "${{ needs.meta.outputs.semver }}"
    runs = "\n".join(step.get("run", "") for step in native["steps"])
    assert "-p opentide-lsp" in runs
    assert "--bin opentide " in runs


@pytest.mark.parametrize("crate", ["opentide-lsp", "opentide-analysis"])
def test_no_crate_reports_its_own_package_version_directly(crate: str) -> None:
    """The reported `VERSION` is the core's; a crate naming CARGO_PKG_VERSION
    again would report `1.0.0` from a candidate's binary."""
    text = (ROOT / "crates" / crate / "src" / "lib.rs").read_text(encoding="utf-8")
    assert "pub const VERSION: &str = opentide_core::VERSION;" in text
    assert 'env!("CARGO_PKG_VERSION")' not in text
