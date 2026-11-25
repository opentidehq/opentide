"""``report_version.py``: make a build of the wheel or the sdist report its own version.

The wheels and the sdist are built from the branch's workspace, whose crates keep
the release's ``X.Y.Z``; a candidate's wheel is ``X.Y.ZrcN`` and a CI build's
``X.Y.Z.devN``, which ``scripts/engine/release.py pypi-version`` writes into the
binding's crate alone. The engine (``opentide-analysis``) and the language server
report ``opentide_core::VERSION``: ``OPENTIDE_BUILD_VERSION`` when the build sets it,
else their crate's version. So the build sets it, in SemVer (``X.Y.Z-rc.N``), in
the checkout's ``.cargo/config.toml`` (``[env]``): cargo reads it wherever it runs,
inside maturin's manylinux container too, and an sdist that carries the file builds
the same on a user's machine::

    python scripts/build/report_version.py 1.0.0rc1     # OPENTIDE_BUILD_VERSION = "1.0.0-rc.1"

Only a release's or a candidate's version is set. A CI build's (``X.Y.Z.devN``) is
left alone: the value sits at the bottom of the crate graph (``opentide-core``), so a
change of it rebuilds nearly every crate, and a development wheel would miss the
compiler cache on every run. Its engine reports the crates' version, as before.

The variable is a build-only name, never ``OPENTIDE_VERSION``: that is the pip pin
``opentide setup ci`` writes into the pipelines it generates (a workflow-level
variable there would otherwise stamp a ``cargo install`` inside such a job).

Run in the workflow's checkout, never committed. It replaces an earlier value, so
it can run twice.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".cargo" / "config.toml"
#: The build-time variable `opentide_core::VERSION` reads (`option_env!`).
VARIABLE = "OPENTIDE_BUILD_VERSION"
MARK = "# The version this build reports (scripts/build/report_version.py)."
BLOCK = re.compile(rf"\n*{re.escape(MARK)}\n\[env\]\n{VARIABLE} = \"[^\"]*\"\n", re.MULTILINE)


def cargo_version(pypi_version: str) -> str:
    """The SemVer spelling of a wheel's version (`release.py`'s `cargo_version`)."""
    path = ROOT / "scripts" / "engine" / "release.py"
    spec = importlib.util.spec_from_file_location("opentide_engine_release", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return str(module.cargo_version(pypi_version))


def render(text: str, version: str) -> str:
    """`text`, a `.cargo/config.toml`, with the build variable set to `version`."""
    return BLOCK.sub("", text).rstrip("\n") + f'\n\n{MARK}\n[env]\n{VARIABLE} = "{version}"\n'


def main(argv: list[str]) -> None:
    if len(argv) != 1:
        sys.exit("usage: report_version.py PYPI_VERSION (X.Y.Z, X.Y.ZrcN or X.Y.Z.devN)")
    try:
        version = cargo_version(argv[0])
    except ValueError as error:
        sys.exit(f"report_version: {error}")
    if re.search(r"-dev\.", version):
        print(f"{VARIABLE} not set: {argv[0]} is a development build (it would miss the cache)")
        return
    original = CONFIG.read_text(encoding="utf-8") if CONFIG.is_file() else ""
    CONFIG.parent.mkdir(exist_ok=True)
    CONFIG.write_text(render(original, version), encoding="utf-8", newline="\n")
    print(f"{VARIABLE} = {version}")


if __name__ == "__main__":
    main(sys.argv[1:])
