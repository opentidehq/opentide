"""The build that compiles the engine into the wheel: maturin, ``[tool.maturin]``."""

from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]


def _toml(relative: str) -> dict:
    return tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))


def _maturin() -> dict:
    return _toml("pyproject.toml")["tool"]["maturin"]


def _glob(pattern: str) -> re.Pattern[str]:
    parts = re.split(r"(\*\*/|\*\*|\*)", pattern)
    table = {"**/": "(?:.*/)?", "**": ".*", "*": "[^/]*"}
    return re.compile("".join(table.get(part, re.escape(part)) for part in parts))


def test_maturin_builds_the_package_from_the_binding() -> None:
    """A mixed layout: the Python sources in src/, the extension at opentide/_native."""
    pyproject = _toml("pyproject.toml")
    assert pyproject["build-system"]["build-backend"] == "maturin"
    (requirement,) = pyproject["build-system"]["requires"]
    assert re.fullmatch(r"maturin==\d+\.\d+\.\d+", requirement), "pin maturin's version"
    maturin = _maturin()
    assert maturin["python-source"] == "src"
    assert maturin["module-name"] == "opentide._native"
    assert maturin["manifest-path"] == "bindings/python/Cargo.toml"
    assert maturin["bindings"] == "pyo3"
    # A wheel is a release build; development builds pass --profile.
    assert maturin["profile"] == "release"


def test_the_version_is_the_cargo_workspaces() -> None:
    """No version in pyproject: maturin reads the binding's, the workspace's
    (`scripts/engine/release.py bump`), so the wheel and the crates carry one."""
    project = _toml("pyproject.toml")["project"]
    assert "version" not in project
    assert "version" in project["dynamic"]
    binding = _toml("bindings/python/Cargo.toml")["package"]
    assert binding["version"] == {"workspace": True}


def test_one_abi3_wheel_per_platform() -> None:
    """pyo3's abi3-py310 feature: maturin tags the wheel cp310-abi3-<platform>."""
    binding = _toml("bindings/python/Cargo.toml")
    assert "abi3-py310" in binding["dependencies"]["pyo3"]["features"]
    assert binding["lib"] == {"name": "_native", "crate-type": ["cdylib"]}


def test_the_stub_ships_while_compiled_modules_stay_out_of_the_sdist() -> None:
    """A ``_native.*`` exclude matched ``_native.pyi`` too, so no stub reached users."""
    excluded = [
        _glob(entry["path"]) for entry in _maturin()["exclude"] if entry["format"] == "sdist"
    ]

    def dropped(file: str) -> bool:
        return any(pattern.fullmatch(f"src/opentide/{file}") for pattern in excluded)

    for stub in ("_native/__init__.pyi", "_native/models.pyi", "_native/sdk.pyi", "py.typed"):
        assert not dropped(stub), stub
    for module in (
        "_native.abi3.so",
        "_native.so",
        "_native.pyd",
        "_native.cpython-314t-x86_64-linux-gnu.so",
        "_native.cp314t-win_amd64.pyd",
    ):
        assert dropped(module), module


def test_the_sdist_carries_what_the_crates_compile_in() -> None:
    """The engine crates read the catalogs and highlight data from
    the repository root, and the workspace patches two crates from vendor/:
    cargo packages none of them with a crate, so the sdist adds them."""
    included = {entry["path"] for entry in _maturin()["include"] if entry["format"] == "sdist"}
    assert {
        "data/catalogs/**/*",
        "highlights/spec.toml",
        "highlights/queries/**/*",
        "vendor/**/*",
    } <= included
    patches = _toml("Cargo.toml")["patch"]["crates-io"]
    for spec in patches.values():
        assert _glob("vendor/**/*").fullmatch(f"{spec['path']}/Cargo.toml"), spec


def test_the_wheel_leaves_out_the_data_the_binary_compiles_in() -> None:
    """build.rs and ``include_str!`` read src/opentide/data and src/opentide/schemas
    at build time and nothing reads them at run time: the wheel excludes them, the
    sdist (which the build needs them in) does not."""
    entries = _maturin()["exclude"]
    wheel = [_glob(entry["path"]) for entry in entries if entry["format"] == "wheel"]
    sdist = [_glob(entry["path"]) for entry in entries if entry["format"] == "sdist"]
    for file in (
        "src/opentide/data/diagnostics/analysis_engine.md",
        "src/opentide/data/configurations/platforms/splunk.toml",
        "src/opentide/schemas/data/platform_templates/splunk.json",
    ):
        assert any(pattern.fullmatch(file) for pattern in wheel), file
        assert not any(pattern.fullmatch(file) for pattern in sdist), file
    for kept in (
        "src/opentide/__init__.py",
        "src/opentide/py.typed",
        "src/opentide/_native/sdk.pyi",
    ):
        assert not any(pattern.fullmatch(kept) for pattern in wheel), kept


def test_the_engine_crate_is_a_member_of_the_root_workspace() -> None:
    """``bindings/python/`` builds the engine crates of this repository by path, in the one Cargo
    workspace and lock at the root (#800): a ``[workspace]`` table or a lock of its own
    would resolve the engine apart from ``crates/``, as the crates.io pin used to."""
    root = _toml("Cargo.toml")
    manifest = _toml("bindings/python/Cargo.toml")
    assert "bindings/python" in root["workspace"]["members"]
    assert "workspace" not in manifest
    assert not (ROOT / "bindings" / "python" / "Cargo.lock").exists()
    # The engine comes through the facade alone (UC-5.1, #836), by path in this workspace.
    assert manifest["dependencies"]["opentide"]["path"] == "../../crates/opentide"
    internal = sorted(name for name in manifest["dependencies"] if name.startswith("opentide-"))
    assert internal == []
    # Development builds (`maturin develop --profile develop`) build it.
    assert root["profile"]["develop"]["inherits"] == "release"
