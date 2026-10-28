"""The build hook that compiles the engine into the wheel (``hatch_build.py``)."""

from __future__ import annotations

import importlib.util
import sys
import sysconfig
import types
from collections.abc import Iterator
from pathlib import Path

import pytest

from opentide.core.files import tomllib

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def hook(monkeypatch: pytest.MonkeyPatch) -> Iterator[types.ModuleType]:
    """``hatch_build`` loaded with a stand-in for hatchling, which only builds have."""
    interface = types.ModuleType("hatchling.builders.hooks.plugin.interface")
    interface.BuildHookInterface = object  # type: ignore[attr-defined]
    for name in ("hatchling", "hatchling.builders", "hatchling.builders.hooks"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "hatchling.builders.hooks.plugin", types.ModuleType("p"))
    monkeypatch.setitem(sys.modules, interface.__name__, interface)
    spec = importlib.util.spec_from_file_location("hatch_build", ROOT / "hatch_build.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module


def _gil_disabled(monkeypatch: pytest.MonkeyPatch, disabled: bool) -> None:
    real = sysconfig.get_config_var

    def config_var(name: str) -> object:
        if name == "Py_GIL_DISABLED":
            return 1 if disabled else 0
        if name == "EXT_SUFFIX" and disabled:
            return ".cpython-314t-x86_64-linux-gnu.so"
        return real(name)

    monkeypatch.setattr(sysconfig, "get_config_var", config_var)


def test_a_cpython_with_the_gil_builds_one_abi3_wheel(
    hook: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _gil_disabled(monkeypatch, False)
    monkeypatch.setattr(sys.implementation, "name", "cpython")
    assert hook.stable_abi()
    assert hook.wheel_tag().startswith("cp310-abi3-")
    assert hook.module_name() in {"_native.abi3.so", "_native.pyd"}


def test_a_free_threaded_cpython_builds_for_itself(
    hook: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """3.14t has no stable ABI: a cp310-abi3 tag made uv refuse the wheel it built."""
    _gil_disabled(monkeypatch, True)
    monkeypatch.setattr(sys.implementation, "name", "cpython")
    assert not hook.stable_abi()
    assert "abi3" not in hook.wheel_tag()
    assert hook.module_name() == "_native.cpython-314t-x86_64-linux-gnu.so"


@pytest.mark.parametrize(
    ("target", "host", "expected"),
    [
        (None, "x86_64-unknown-linux-musl", True),
        (None, "aarch64-unknown-linux-musl", True),
        (None, "x86_64-unknown-linux-gnu", False),
        ("x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu", True),
        ("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl", False),
        (None, None, False),
    ],
)
def test_musl_is_read_from_the_target_then_the_host(
    hook: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    target: str | None,
    host: str | None,
    expected: bool,
) -> None:
    """musl links its C runtime statically by default, and rustc then drops the cdylib."""
    if target is None:
        monkeypatch.delenv("CARGO_BUILD_TARGET", raising=False)
    else:
        monkeypatch.setenv("CARGO_BUILD_TARGET", target)
    assert hook.builds_for_musl(host) is expected


def test_rust_host_reads_rustc(hook: types.ModuleType) -> None:
    import shutil

    rustc = shutil.which("rustc")
    if rustc is None:
        pytest.skip("rustc is not installed")
    assert hook.rust_host(rustc)
    assert hook.rust_host(None) is None


def test_the_stub_ships_while_compiled_modules_stay_out() -> None:
    """A ``_native.*`` exclude matched ``_native.pyi`` too, so no stub reached users."""
    from fnmatch import fnmatch

    build = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    targets = build["tool"]["hatch"]["build"]["targets"]
    for name, prefix in (("wheel", "src/opentide/"), ("sdist", "/src/opentide/")):
        excluded = targets[name]["exclude"]

        def dropped(file: str, excluded: list[str] = excluded, prefix: str = prefix) -> bool:
            return any(fnmatch(prefix + file, pattern) for pattern in excluded)

        assert not dropped("_native.pyi"), name
        for module in (
            "_native.abi3.so",
            "_native.so",
            "_native.pyd",
            "_native.cpython-314t-x86_64-linux-gnu.so",
            "_native.cp314t-win_amd64.pyd",
        ):
            assert dropped(module), (name, module)


def test_macos_wheels_target_rustcs_floor() -> None:
    build = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    environment = build["tool"]["cibuildwheel"]["macos"]["environment"]
    assert environment["MACOSX_DEPLOYMENT_TARGET"] == "10.12"
