"""Build the analysis engine into the opentide wheel.

The engine is Rust: ``bindings/python/``, the PyO3 bindings for the engine crates in
``crates/``, all members of the Cargo workspace at the repository root. This
hook compiles it with cargo and puts it in the wheel as ``opentide/_native``
(``.abi3.so``, or ``.pyd`` on Windows), so ``pip install opentide`` is the one
install: there is no separate engine distribution. The extension uses the
stable ABI from CPython 3.10, so the wheel is tagged ``cp310-abi3-<platform>``:
one wheel per platform serves every CPython from 3.10 on. A free-threaded
CPython (3.14t) or another implementation has no stable ABI: a wheel built
there is tagged for that interpreter alone.

- A wheel builds with cargo's ``release`` profile.
- An editable install (``uv sync``) builds the ``develop`` profile, which skips
  link-time optimisation, and puts the module in ``src/opentide/``.
- ``OPENTIDE_ENGINE_PROFILE`` picks another profile (the wheel install tests
  build ``develop`` wheels).

Building needs a Rust toolchain (stable, see ``rust-version`` in
``Cargo.toml``). The library is wherever cargo reports writing it, so
``CARGO_TARGET_DIR`` and ``CARGO_BUILD_TARGET`` are honoured. On musl (Alpine,
the musllinux images) cargo is told to link the C runtime dynamically: Rust's
musl targets link it statically by default, and then cannot build a shared
library at all. The release workflow publishes a wheel for each supported
platform; elsewhere, pip builds from the sdist, which carries the workspace's
manifests, sources and embedded data.
"""

from __future__ import annotations

import json
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
MANIFEST = ROOT / "Cargo.toml"
#: The workspace member ``bindings/python/``, and its ``cdylib`` target.
PACKAGE = "opentide-native"
LIBRARY = "_native"
PROFILE_ENV = "OPENTIDE_ENGINE_PROFILE"
#: The oldest CPython whose stable ABI the extension uses (``abi3-py310``).
ABI3_FLOOR = "cp310"


def stable_abi() -> bool:
    """Whether this interpreter loads a stable-ABI (``abi3``) extension: a CPython with the GIL."""
    return sys.implementation.name == "cpython" and not sysconfig.get_config_var("Py_GIL_DISABLED")


def module_name() -> str:
    """The extension's file name in the package, as this interpreter imports it."""
    if not stable_abi():
        return "_native" + str(sysconfig.get_config_var("EXT_SUFFIX"))
    return "_native.pyd" if sys.platform == "win32" else "_native.abi3.so"


def wheel_tag() -> str:
    """``cp310-abi3-<platform>`` on a CPython with the GIL; this interpreter's own tag otherwise."""
    if stable_abi():
        return f"{ABI3_FLOOR}-abi3-{platform_tag()}"
    from packaging.tags import sys_tags

    return str(next(iter(sys_tags())))


def builds_for_musl(rust_host: str | None) -> bool:
    """Whether cargo builds for a musl target: ``CARGO_BUILD_TARGET``, else rustc's host."""
    target = os.environ.get("CARGO_BUILD_TARGET") or rust_host or ""
    return target.endswith("musl")


def rust_host(rustc: str | None) -> str | None:
    """rustc's host triple (``x86_64-unknown-linux-musl``), or ``None`` when rustc does not say.

    A rustc that fails is an error, with what it printed: through rustup's
    proxy it can be a toolchain install that failed (rust-toolchain.toml),
    which cargo would otherwise meet later as a less telling error.
    """
    if rustc is None:
        return None
    command = [rustc, "-vV"]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(
            f"`{' '.join(command)}` exited with status {done.returncode}:\n"
            f"{(done.stderr or '').strip() or '(no output on stderr)'}"
        )
    version = done.stdout
    return next(
        (
            line.split(":", 1)[1].strip()
            for line in version.splitlines()
            if line.startswith("host:")
        ),
        None,
    )


def built_library(messages: str) -> Path:
    """The ``_native`` library cargo reports writing, in its JSON *messages*.

    Read from cargo rather than guessed, so it is right whatever the target
    directory (``CARGO_TARGET_DIR``, a workspace's ``target/``), the profile, or a
    cross build's ``target/<triple>/``.
    """
    for line in messages.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target") or {}
        if target.get("name") != LIBRARY or "cdylib" not in target.get("kind", []):
            continue
        for filename in message.get("filenames", []):
            if Path(filename).suffix in {".so", ".dylib", ".dll"}:
                return Path(filename)
    raise RuntimeError(f"cargo reported no {LIBRARY} library for {PACKAGE}")


def platform_tag() -> str:
    """This interpreter's platform as a wheel tag (``linux_x86_64``,
    ``macosx_11_0_arm64``, ``win_amd64``); auditwheel and delocate refine it."""
    return sysconfig.get_platform().replace("-", "_").replace(".", "_")


def pyo3_python() -> str:
    """The interpreter PyO3 reads its configuration from: ``PYO3_PYTHON``, else
    the base interpreter of the one running this build.

    Every build (``uv sync``, ``uv build``, pip) runs in an isolated environment
    of its own, at a new path each time. PyO3's build script reruns whenever
    ``PYO3_PYTHON`` changes, and cargo then rebuilds pyo3 and every engine crate
    above it, minutes of work for the same configuration: the environment's base
    interpreter answers PyO3 alike and stays put from one build to the next.
    """
    explicit = os.environ.get("PYO3_PYTHON")
    if explicit:
        return explicit
    base = getattr(sys, "_base_executable", None)
    if base and Path(base).is_file():
        return str(base)
    return sys.executable


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
        "PYO3_PYTHON": pyo3_python(),
    }
    if builds_for_musl(rust_host(shutil.which("rustc"))):
        # musl links its C runtime statically by default, which rules out a cdylib.
        flags = env.get("RUSTFLAGS", "")
        env["RUSTFLAGS"] = f"{flags} -C target-feature=-crt-static".strip()
    command = [cargo, "build", "--manifest-path", str(MANIFEST), "-p", PACKAGE, "--lib", "--locked"]
    command += ["--profile", profile, "--message-format=json-render-diagnostics"]
    # The JSON messages on stdout name the library; diagnostics and progress
    # stay on stderr, as cargo renders them. cargo writes them in UTF-8; the
    # locale's encoding (Windows' ANSI code page) would garble a non-ASCII path.
    result = subprocess.run(
        command, check=True, env=env, stdout=subprocess.PIPE, text=True, encoding="utf-8"
    )
    library = built_library(result.stdout)
    if not library.is_file():
        raise RuntimeError(f"cargo did not write {library}")
    return library


class EngineBuildHook(BuildHookInterface):
    """Compile ``bindings/python/`` into ``opentide/_native`` for every wheel, editable included."""

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
        build_data["tag"] = wheel_tag()

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        staging = getattr(self, "_staging", None)
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
