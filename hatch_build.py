"""Build the analysis engine into the opentide wheel.

The engine is Rust (``analysis/``: PyO3 bindings for the crates of
opentidehq/language-server). This hook compiles it with cargo and puts it in
the wheel as ``opentide/_native`` (``.abi3.so``, or ``.pyd`` on Windows), so
``pip install opentide`` is the one install: there is no separate engine
distribution. The extension uses the stable ABI from CPython 3.10, so the
wheel is tagged ``cp310-abi3-<platform>``: one wheel per platform serves every
CPython from 3.10 on.

- A wheel builds with cargo's ``release`` profile.
- An editable install (``uv sync``) builds the ``develop`` profile, which skips
  link-time optimisation, and puts the module in ``src/opentide/``.
- ``OPENTIDE_ENGINE_PROFILE`` picks another profile (the wheel install tests
  build ``develop`` wheels).

Building needs a Rust toolchain (stable, see ``rust-version`` in
``analysis/Cargo.toml``). The release workflow publishes a wheel for each
supported platform; elsewhere, pip builds from the sdist, which carries
``analysis/``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "analysis" / "Cargo.toml"
TARGET = ROOT / "analysis" / "target"
PROFILE_ENV = "OPENTIDE_ENGINE_PROFILE"
#: The oldest CPython whose stable ABI the extension uses (``abi3-py310``).
ABI3_FLOOR = "cp310"


def module_name() -> str:
    """The extension's file name in the package, as CPython imports it."""
    return "_native.pyd" if sys.platform == "win32" else "_native.abi3.so"


def built_library(profile: str) -> Path:
    """What cargo writes for the ``_native`` cdylib under *profile*."""
    directory = TARGET / ("debug" if profile == "dev" else profile)
    # A cross build (CARGO_BUILD_TARGET) writes under target/<triple>/.
    triple = os.environ.get("CARGO_BUILD_TARGET")
    if triple:
        directory = TARGET / triple / directory.name
    if sys.platform == "win32":
        return directory / "_native.dll"
    if sys.platform == "darwin":
        return directory / "lib_native.dylib"
    return directory / "lib_native.so"


def platform_tag() -> str:
    """This interpreter's platform as a wheel tag (``linux_x86_64``,
    ``macosx_11_0_arm64``, ``win_amd64``); auditwheel and delocate refine it."""
    return sysconfig.get_platform().replace("-", "_").replace(".", "_")


def build_engine(profile: str) -> Path:
    """Compile the extension; return the library cargo wrote."""
    cargo = shutil.which("cargo")
    if cargo is None:
        raise RuntimeError(
            "Building opentide compiles its analysis engine, which is Rust: install a Rust "
            "toolchain (https://rustup.rs) and build again. Released versions ship a wheel for "
            "Linux, macOS and Windows that needs none."
        )
    env = {
        **os.environ,
        # No libpython link: the interpreter that imports the module provides it.
        "PYO3_BUILD_EXTENSION_MODULE": "1",
        # The interpreter running this build, for PyO3's configuration.
        "PYO3_PYTHON": os.environ.get("PYO3_PYTHON", sys.executable),
    }
    command = [cargo, "build", "--manifest-path", str(MANIFEST), "--lib", "--locked"]
    command += ["--profile", profile]
    subprocess.run(command, check=True, env=env)
    library = built_library(profile)
    if not library.is_file():
        raise RuntimeError(f"cargo did not write {library}")
    return library


class EngineBuildHook(BuildHookInterface):
    """Compile ``analysis/`` into ``opentide/_native`` for every wheel, editable included."""

    PLUGIN_NAME = "opentide-engine"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel":
            return
        editable = version == "editable"
        profile = os.environ.get(PROFILE_ENV) or ("develop" if editable else "release")
        library = build_engine(profile)
        name = module_name()
        if editable:
            # The editable wheel points at src/: the module goes next to the sources.
            shutil.copy2(library, ROOT / "src" / "opentide" / name)
        else:
            self._staging = Path(tempfile.mkdtemp(prefix="opentide-engine-"))
            staged = self._staging / name
            shutil.copy2(library, staged)
            build_data["force_include"][str(staged)] = f"opentide/{name}"
        build_data["pure_python"] = False
        build_data["tag"] = f"{ABI3_FLOOR}-abi3-{platform_tag()}"

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        staging = getattr(self, "_staging", None)
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
