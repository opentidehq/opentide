"""The build hook that compiles the engine into the wheel (``hatch_build.py``)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
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

        for stub in ("_native/__init__.pyi", "_native/models.pyi"):
            assert not dropped(stub), (name, stub)
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


def test_the_engine_crate_is_a_member_of_the_root_workspace() -> None:
    """``analysis/`` builds the engine crates of this repository by path, in the one Cargo
    workspace and lock at the root (#800): a ``[workspace]`` table or a lock of its own
    would resolve the engine apart from ``crates/``, as the crates.io pin used to."""
    root = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    manifest = tomllib.loads((ROOT / "analysis" / "Cargo.toml").read_text(encoding="utf-8"))
    assert "analysis" in root["workspace"]["members"]
    assert "workspace" not in manifest
    assert not (ROOT / "analysis" / "Cargo.lock").exists()
    for crate in ("opentide-analysis", "opentide-lsp"):
        assert manifest["dependencies"][crate] == {"workspace": True}
        assert root["workspace"]["dependencies"][crate]["path"] == f"crates/{crate}"
    # hatch_build.py builds an editable install with it.
    assert root["profile"]["develop"]["inherits"] == "release"


def _artifact(name: str, kind: list[str], filenames: list[str]) -> str:
    target = {"name": name, "kind": kind}
    return json.dumps({"reason": "compiler-artifact", "target": target, "filenames": filenames})


def test_the_library_is_where_cargo_reports_writing_it(hook: types.ModuleType) -> None:
    """Not a path guessed from the manifest: CARGO_TARGET_DIR, the workspace's target/
    and a cross build's target/<triple>/ all move it."""
    messages = "\n".join(
        [
            "not json",
            json.dumps({"reason": "build-script-executed", "package_id": "pyo3"}),
            _artifact("opentide_analysis", ["lib"], ["/t/develop/libopentide_analysis.rlib"]),
            _artifact("_native", ["cdylib"], ["/elsewhere/develop/lib_native.so"]),
            json.dumps({"reason": "build-finished", "success": True}),
        ]
    )
    assert hook.built_library(messages) == Path("/elsewhere/develop/lib_native.so")


def test_a_windows_build_reports_the_dll_beside_its_import_library(
    hook: types.ModuleType,
) -> None:
    files = ["C:/t/release/_native.dll.lib", "C:/t/release/_native.dll", "C:/t/release/_native.pdb"]
    assert hook.built_library(_artifact("_native", ["cdylib"], files)) == Path(
        "C:/t/release/_native.dll"
    )


def test_cargo_reporting_no_library_is_an_error(hook: types.ModuleType) -> None:
    with pytest.raises(RuntimeError, match="no _native library"):
        hook.built_library(json.dumps({"reason": "build-finished", "success": True}))


def test_the_build_asks_cargo_for_the_workspace_member_and_its_messages(
    hook: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    library = tmp_path / "custom-target" / "develop" / "lib_native.so"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"\x7fELF")
    seen: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(command)
        stdout = _artifact("_native", ["cdylib"], [str(library)])
        return subprocess.CompletedProcess(command, 0, stdout=stdout)

    monkeypatch.setattr(hook.shutil, "which", lambda name: name if name == "cargo" else None)
    monkeypatch.setattr(hook.subprocess, "run", run)
    assert hook.build_engine("develop") == library
    command = seen[-1]
    assert command[command.index("--manifest-path") + 1] == str(ROOT / "Cargo.toml")
    assert command[command.index("-p") + 1] == "opentide-native"
    assert "--locked" in command
    assert "--message-format=json-render-diagnostics" in command


def test_cargos_messages_are_read_as_utf8_whatever_the_locale(
    hook: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """cargo writes its JSON in UTF-8, unescaped. Text mode without an encoding
    decodes it with the locale's: Windows' ANSI code page turns a build under
    C:\\Users\\Zoë into ZoÃ«, a library that does not exist."""
    library = tmp_path / "Zoë" / "release" / "_native.dll"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"MZ")

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        target = {"name": "_native", "kind": ["cdylib"]}
        message = {"reason": "compiler-artifact", "target": target, "filenames": [str(library)]}
        raw = json.dumps(message, ensure_ascii=False).encode("utf-8")
        assert kwargs.get("text") or kwargs.get("encoding"), "cargo's messages are text"
        # What subprocess does with text=True: the given encoding, else the locale's.
        encoding = kwargs.get("encoding") or "cp1252"
        assert isinstance(encoding, str)
        return subprocess.CompletedProcess(command, 0, stdout=raw.decode(encoding))

    monkeypatch.setattr(hook.shutil, "which", lambda name: name if name == "cargo" else None)
    monkeypatch.setattr(hook.subprocess, "run", run)
    assert hook.build_engine("release") == library
