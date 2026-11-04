"""``check_engine_pin.py``: the engine crates come from one source, and a release from crates.io.

``analysis/`` binds two crates of opentidehq/language-server,
``opentide-analysis`` and ``opentide-lsp``, which pin each other: both must
come from the same git revision, path or version.

``--release`` also refuses a ``git`` or ``path`` source: between
language-server releases ``analysis/Cargo.toml`` may build from a git
revision, but a published opentide wheel and sdist build from crates.io, so
anyone can rebuild them from the sdist.

    uv run python scripts/build/check_engine_pin.py
    uv run python scripts/build/check_engine_pin.py --release
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
ENGINE_CRATES = ("opentide-analysis", "opentide-lsp")


def problems(root: Path, *, release: bool) -> list[str]:
    """What is wrong, one sentence each; empty when everything agrees."""
    found: list[str] = []
    cargo = tomllib.loads((root / "analysis" / "Cargo.toml").read_text(encoding="utf-8"))
    sources = {name: cargo["dependencies"].get(name) for name in ENGINE_CRATES}
    for name, spec in sources.items():
        if spec is None:
            found.append(f"analysis/Cargo.toml does not depend on {name}")
        elif release and isinstance(spec, dict) and ("git" in spec or "path" in spec):
            found.append(
                f"analysis/Cargo.toml takes {name} from {spec.get('git') or spec.get('path')}: "
                "a release builds from crates.io; publish the language server and pin "
                f'{name} = "=<version>"'
            )
    shapes = {_source(spec) for spec in sources.values() if spec is not None}
    if len(shapes) > 1:
        found.append(f"{' and '.join(ENGINE_CRATES)} must come from the same source and version")
    return found


def _source(spec: object) -> tuple[str, ...]:
    """Where a dependency comes from: a version, a git revision, or a local checkout."""
    if not isinstance(spec, dict):
        # `"=0.5.0"` is `{ version = "=0.5.0" }`.
        spec = {"version": spec}
    if "path" in spec:
        # Each crate has its own folder in the one checkout.
        return ("path", str(Path(spec["path"]).parent))
    return tuple(
        f"{key}={spec[key]}" for key in ("git", "rev", "tag", "branch", "version") if key in spec
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release", action="store_true", help="also require crates.io sources")
    args = parser.parse_args(argv)
    found = problems(ROOT, release=args.release)
    for problem in found:
        print(f"error: {problem}", file=sys.stderr)
    if not found:
        print("the engine crates come from one source")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
