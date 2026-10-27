"""Refuse a release that changed the engine but kept a version PyPI already has.

The publish workflow uploads ``opentide-analysis`` with ``skip-existing``, so a
version already on PyPI uploads nothing. If ``analysis/`` changed since that
upload (a new engine revision in ``Cargo.toml``, a new binding in
``src/lib.rs``), the release would ship opentide pinned to the *old* engine.
This compares the sources of the version on PyPI, read from its sdist, with
the checkout and fails when they differ: bump the version first.

    python scripts/build/check_engine_published.py

Exit 0 when the version is not on PyPI yet, or when its sources match.
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "opentide-analysis"
PYPI = "https://pypi.org/pypi"
#: The files that make the engine package, relative to ``analysis/``.
SOURCES = ("Cargo.toml", "pyproject.toml", "src/lib.rs")
PYTHON_SOURCES = "python/opentide_analysis/"


def local_sources(root: Path) -> dict[str, bytes]:
    analysis = root / "analysis"
    files = {name: (analysis / name).read_bytes() for name in SOURCES}
    for path in sorted((analysis / PYTHON_SOURCES).glob("*")):
        if path.is_file() and path.suffix in {".py", ".pyi", ".typed"}:
            files[f"{PYTHON_SOURCES}{path.name}"] = path.read_bytes()
    return files


def sdist_sources(archive: bytes) -> dict[str, bytes]:
    """The engine's files in a maturin sdist (``opentide_analysis-X/...``)."""
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name.split("/", 1)[1] if "/" in member.name else member.name
            wanted = name in SOURCES or (
                name.startswith(PYTHON_SOURCES) and "/" not in name[len(PYTHON_SOURCES) :]
            )
            extracted = tar.extractfile(member) if wanted else None
            if extracted is not None:
                files[name] = extracted.read()
    return files


def _normal(name: str, text: bytes) -> object:
    """What decides the build, so a rewrite that changes nothing does not count."""
    if name == "Cargo.toml":
        # maturin adds `readme` to the sdist's manifest; what it builds is the
        # version, the dependencies (the engine revision) and the profiles.
        manifest = tomllib.loads(text.decode("utf-8"))
        return (
            manifest.get("package", {}).get("version"),
            manifest.get("dependencies"),
            manifest.get("profile"),
        )
    return text.replace(b"\r\n", b"\n").strip()


def differences(local: dict[str, bytes], published: dict[str, bytes]) -> list[str]:
    """The engine files whose content differs between the checkout and the sdist."""
    names = sorted(set(local) | set(published))
    return [
        name
        for name in names
        if name not in local
        or name not in published
        or _normal(name, local[name]) != _normal(name, published[name])
    ]


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def main() -> int:
    version = tomllib.loads((ROOT / "analysis" / "pyproject.toml").read_text("utf-8"))["project"][
        "version"
    ]
    try:
        release = json.loads(_fetch(f"{PYPI}/{PACKAGE}/{version}/json"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print(f"{PACKAGE} {version} is not on PyPI yet: this release publishes it")
            return 0
        raise
    sdists = [item for item in release.get("urls", []) if item.get("packagetype") == "sdist"]
    if not sdists:
        print(f"error: {PACKAGE} {version} is on PyPI without an sdist to compare", file=sys.stderr)
        return 1
    changed = differences(local_sources(ROOT), sdist_sources(_fetch(sdists[0]["url"])))
    if changed:
        print(
            f"error: analysis/ changed since {PACKAGE} {version} was published "
            f"({', '.join(changed)}), and PyPI already has that version: bump the version in "
            "analysis/pyproject.toml, analysis/Cargo.toml and the pin in pyproject.toml",
            file=sys.stderr,
        )
        return 1
    print(f"{PACKAGE} {version} on PyPI matches analysis/: nothing new to publish")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
