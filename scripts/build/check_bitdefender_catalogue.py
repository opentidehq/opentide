"""Fail when opentide's Bitdefender criteria catalogue differs from the pinned engine's.

``src/opentide/data/bitdefender/criteria.toml`` is a verbatim copy of
opentidehq/language-server's ``catalogs/bitdefender/criteria.toml``, so
``opentide validate`` and the editor check a Bitdefender block with one set of
fields, relations and pairing rules. This finds the copy in the source of the
engine ``analysis/Cargo.toml`` pins (``cargo metadata``) and compares the two::

    uv run python scripts/build/check_bitdefender_catalogue.py

An engine that carries no catalogue yet has nothing to compare: the check says so
and passes, until the pin moves to an engine that ships it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VENDORED = ROOT / "src" / "opentide" / "data" / "bitdefender" / "criteria.toml"
RELATIVE = Path("catalogs") / "bitdefender" / "criteria.toml"
FIX = """\
  help: copy catalogs/bitdefender/criteria.toml from the pinned language-server revision
        to src/opentide/data/bitdefender/criteria.toml, and check the Bitdefender tests"""


def engine_catalogue(metadata: dict[str, object]) -> Path | None:
    """The catalogue in the pinned ``opentide-analysis`` source tree, or ``None``."""
    packages = metadata.get("packages")
    for package in packages if isinstance(packages, list) else []:
        if not isinstance(package, dict) or package.get("name") != "opentide-analysis":
            continue
        crate = Path(str(package["manifest_path"])).parent
        # A git checkout holds the whole repository; a published crate, its own dir.
        for base in (crate, *crate.parents[:2]):
            if (base / RELATIVE).is_file():
                return base / RELATIVE
    return None


def differs(vendored: Path, pinned: Path) -> bool:
    return vendored.read_bytes().replace(b"\r\n", b"\n") != pinned.read_bytes().replace(
        b"\r\n", b"\n"
    )


def main() -> int:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--manifest-path", "analysis/Cargo.toml"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"error: cargo metadata failed:\n{result.stderr}", file=sys.stderr)
        return 1
    pinned = engine_catalogue(json.loads(result.stdout))
    if pinned is None:
        print("the pinned engine carries no Bitdefender criteria catalogue yet; nothing to compare")
        return 0
    if differs(VENDORED, pinned):
        print(
            f"error: {VENDORED.relative_to(ROOT)} differs from the pinned engine's {pinned}",
            file=sys.stderr,
        )
        print(FIX, file=sys.stderr)
        return 1
    print("the Bitdefender criteria catalogue matches the pinned engine's")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
