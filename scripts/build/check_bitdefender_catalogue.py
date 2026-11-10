"""Fail when opentide's Bitdefender criteria catalogue differs from the pinned engine's.

``src/opentide/data/bitdefender/criteria.toml`` is a verbatim copy of
opentidehq/language-server's ``catalogs/bitdefender/criteria.toml``, so
``opentide validate`` and the editor check a Bitdefender block with one set of
fields, relations and pairing rules. This finds the engine's copy through the
``opentide-tide`` crate ``analysis/Cargo.toml`` pins (``cargo metadata``), where
its ``build.rs`` finds it::

    uv run python scripts/build/check_bitdefender_catalogue.py

- a git source: ``catalogs/`` at the workspace root, two levels above the crate;
- a crates.io source: ``assets/catalogs/`` inside the crate (``release.py vendor``).

Transition: an engine that predates Bitdefender support (no ``src/bitdefender.rs``
in ``opentide-tide`` and no ``catalogs/bitdefender/``) has nothing to compare, and
the check passes saying so. Once the pinned engine supports Bitdefender, a missing
catalogue fails like a different one.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VENDORED = ROOT / "src" / "opentide" / "data" / "bitdefender" / "criteria.toml"
CRATE = "opentide-tide"
CATALOGUE = Path("bitdefender") / "criteria.toml"
FIX = """\
  help: copy catalogs/bitdefender/criteria.toml from the pinned language-server revision
        to src/opentide/data/bitdefender/criteria.toml, and check the Bitdefender tests"""


@dataclass(frozen=True)
class EngineCatalogue:
    """Where the pinned engine keeps its catalogs, and what it says about Bitdefender."""

    #: The ``catalogs`` directory the crate's ``build.rs`` reads.
    catalogs: Path
    #: Whether the engine's ``opentide-tide`` checks Bitdefender blocks.
    supports_bitdefender: bool

    @property
    def path(self) -> Path:
        return self.catalogs / CATALOGUE


def engine_catalogue(metadata: dict[str, object]) -> EngineCatalogue | None:
    """The pinned ``opentide-tide``'s catalogs, as its ``build.rs`` resolves them."""
    packages = metadata.get("packages")
    for package in packages if isinstance(packages, list) else []:
        if not isinstance(package, dict) or package.get("name") != CRATE:
            continue
        crate = Path(str(package["manifest_path"])).parent
        workspace = crate.parent.parent / "catalogs"
        # The checkout wins, as in build.rs: a vendored copy never shadows it.
        catalogs = workspace if workspace.is_dir() else crate / "assets" / "catalogs"
        supports = (crate / "src" / "bitdefender.rs").is_file() or (
            catalogs / "bitdefender"
        ).is_dir()
        return EngineCatalogue(catalogs=catalogs, supports_bitdefender=supports)
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
    engine = engine_catalogue(json.loads(result.stdout))
    if engine is None:
        print(f"error: the pinned engine has no {CRATE} crate", file=sys.stderr)
        return 1
    if not engine.path.is_file():
        if engine.supports_bitdefender:
            print(
                f"error: the pinned engine checks Bitdefender blocks but carries no {engine.path}",
                file=sys.stderr,
            )
            print(FIX, file=sys.stderr)
            return 1
        print("the pinned engine predates Bitdefender support: no catalogue to compare yet")
        return 0
    if differs(VENDORED, engine.path):
        print(
            f"error: {VENDORED.relative_to(ROOT)} differs from the pinned engine's {engine.path}",
            file=sys.stderr,
        )
        print(FIX, file=sys.stderr)
        return 1
    print("the Bitdefender criteria catalogue matches the pinned engine's")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
