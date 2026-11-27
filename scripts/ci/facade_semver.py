#!/usr/bin/env python3
"""Check the API the facade re-exports from the workspace's crates (#1911).

`cargo semver-checks` reads one crate's rustdoc JSON at a time, and rustdoc
does not inline an item re-exported from another crate
(obi1kenobi/cargo-semver-checks#638). Run on `crates/opentide`, it never sees
`opentide::analysis::LanguageId`, defined in opentide-core, nor most of the
facade's API, which the internal crates define: #1902 added a variant to that
exhaustive enum and the facade job passed.

This script closes the gap. For each workspace crate the facade re-exports
from (found in the facade's own rustdoc JSON, through the canonical path of
each `pub use`), it builds that crate's rustdoc JSON at the base and at the
change, keeps only what the facade exposes (the re-exported items, the whole
of a re-exported module, and the modules and `use` items that lead to them),
and runs `cargo semver-checks` on the pair. The internal crates' other items
carry no promise and are left out, so their changes never fail the check.

Majors only (`--release-type minor`): the facade's release decides the
version, and an addition, such as a variant of a `#[non_exhaustive]` enum, is
a minor change, as cargo semver-checks reads it.

Usage (the `facade` job of ci.yml):

    python3 scripts/ci/facade_semver.py --baseline-root <checkout of the base>

Needs a stable toolchain (rustdoc's JSON through RUSTC_BOOTSTRAP, as
cargo semver-checks builds it) and cargo-semver-checks on PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

FACADE = "opentide"
#: The facade's crate name in Rust paths, and in rustdoc's JSON.
FACADE_CRATE = "opentide"

JsonDoc = dict[str, Any]
#: A canonical path inside a crate, without the crate's name: ("codes",).
ItemPath = tuple[str, ...]


def rustdoc_json(root: Path, target: Path, package: str) -> JsonDoc:
    """`package`'s rustdoc JSON, every feature, built from the tree at `root`."""
    env = dict(os.environ, RUSTC_BOOTSTRAP="1", CARGO_TARGET_DIR=str(target))
    # Warnings are not this check's concern: the docs job denies them.
    env.pop("RUSTDOCFLAGS", None)
    subprocess.run(
        [
            "cargo",
            "rustdoc",
            "--quiet",
            "--locked",
            "--package",
            package,
            "--all-features",
            "--lib",
            "--",
            "-Zunstable-options",
            "--output-format",
            "json",
            "--cap-lints",
            "allow",
        ],
        cwd=root,
        env=env,
        check=True,
    )
    path = target / "doc" / f"{package.replace('-', '_')}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def reexports(facade: JsonDoc) -> dict[str, set[ItemPath]]:
    """The items each other crate defines that the facade re-exports, by crate."""
    crates = facade["external_crates"]
    found: dict[str, set[ItemPath]] = {}
    for item in facade["index"].values():
        use = item["inner"].get("use")
        if use is None or use["id"] is None:
            continue
        summary = facade["paths"].get(str(use["id"]))
        if summary is None or summary["crate_id"] == 0:
            continue
        crate = crates[str(summary["crate_id"])]["name"]
        found.setdefault(crate, set()).add(tuple(summary["path"][1:]))
    return found


def workspace_packages(root: Path) -> dict[str, str]:
    """Crate name (`opentide_core`) to package name (`opentide-core`)."""
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    return {package["name"].replace("-", "_"): package["name"] for package in metadata["packages"]}


def named_types(node: Any) -> set[int]:
    """The ids of the types `node` (a rustdoc JSON value) names by path."""
    found: set[int] = set()
    stack = [node]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            path = value.get("resolved_path")
            if isinstance(path, dict) and isinstance(path.get("id"), int):
                found.add(path["id"])
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return found


def children(inner: JsonDoc) -> list[int]:
    """The item ids an item owns: its impls, fields, variants and impl items."""
    owned: list[int] = []
    for kind in ("struct", "enum", "union", "trait", "impl", "variant"):
        body = inner.get(kind)
        if not isinstance(body, dict):
            continue
        owned.extend(body.get("impls") or [])
        owned.extend(body.get("variants") or [])
        owned.extend(body.get("items") or [])
        shape = body.get("kind")
        if isinstance(shape, dict):
            plain = shape.get("plain")
            if isinstance(plain, dict):
                owned.extend(plain.get("fields") or [])
            owned.extend(field for field in shape.get("tuple") or [] if field is not None)
            owned.extend(shape.get("struct", {}).get("fields") or [])
    return [child for child in owned if isinstance(child, int)]


def prune(doc: JsonDoc, kept: set[ItemPath]) -> tuple[JsonDoc, list[ItemPath]]:
    """`doc` with only the public paths that lead to the `kept` items.

    Returns the pruned document and the kept paths it does not define.
    """
    index = doc["index"]
    by_path = {
        tuple(summary["path"][1:]): int(item_id)
        for item_id, summary in doc["paths"].items()
        if summary["crate_id"] == 0
    }
    missing = sorted(path for path in kept if path not in by_path)
    reached: set[int] = set()

    def reach(item_id: int) -> None:
        if item_id in reached:
            return
        reached.add(item_id)
        item = index.get(str(item_id))
        if item is not None and "module" in item["inner"]:
            for child in item["inner"]["module"]["items"]:
                reach(child)

    for path in kept:
        if path in by_path:
            reach(by_path[path])

    # The types the reached items name in their signatures, fields, variants
    # and impls: `rule.configurations.elastic` hands a caller an `ElasticConfig`
    # the facade never names, and its fields are the facade's API too.
    local = {int(item_id) for item_id, summary in doc["paths"].items() if summary["crate_id"] == 0}
    pending = list(reached)
    scanned: set[int] = set()
    while pending:
        item_id = pending.pop()
        if item_id in scanned:
            continue
        scanned.add(item_id)
        item = index.get(str(item_id))
        if item is None:
            continue
        for named in named_types(item["inner"]):
            if named in local and named not in reached:
                reach(named)
                pending.append(named)
        # An impl's items and a struct's or enum's fields and variants are
        # items of their own: scan them as well.
        for child in children(item["inner"]):
            pending.append(child)

    def leads(item_id: int) -> bool:
        """Whether a public path through `item_id` reaches a kept item."""
        item = index.get(str(item_id))
        if item is None:
            return False
        if item_id in reached:
            return True
        inner = item["inner"]
        if "use" in inner:
            target = inner["use"]["id"]
            if target is None:
                return False
            if inner["use"]["is_glob"]:
                return any(leads(child) for child in module_items(target))
            return target in reached
        if "module" in inner:
            items = [child for child in inner["module"]["items"] if leads(child)]
            inner["module"]["items"] = items
            return bool(items)
        return False

    def module_items(item_id: int) -> list[int]:
        item = index.get(str(item_id))
        if item is None or "module" not in item["inner"]:
            return []
        return list(item["inner"]["module"]["items"])

    root = index[str(doc["root"])]
    root["inner"]["module"]["items"] = [
        child for child in root["inner"]["module"]["items"] if leads(child)
    ]
    return doc, missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--current-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="where the JSON documents and the baseline's target go (a temporary directory)",
    )
    args = parser.parse_args()
    work = args.work_dir or Path(tempfile.mkdtemp(prefix="facade-semver-"))
    work.mkdir(parents=True, exist_ok=True)
    # One target per tree: cargo judges a workspace crate fresh by modification
    # times, so two trees in one target directory could hand one the other's build.
    current_target = Path(
        os.environ.get("CARGO_TARGET_DIR", args.current_root / "target")
    ).resolve()
    baseline_target = (work / "baseline-target").resolve()

    sides = {
        "current": (args.current_root.resolve(), current_target),
        "baseline": (args.baseline_root.resolve(), baseline_target),
    }
    exposed = {
        side: reexports(rustdoc_json(root, target, FACADE))
        for side, (root, target) in sides.items()
    }
    packages = {side: workspace_packages(root) for side, (root, _) in sides.items()}

    # The `facade` job runs on a change to these crates' sources
    # (scripts/ci/changes.py): a crate missing there would go unchecked.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from changes import FACADE_SOURCES

    unlisted = sorted(
        packages["current"][crate]
        for crate in exposed["current"]
        if crate in packages["current"]
        and crate != FACADE_CRATE
        and packages["current"][crate] not in FACADE_SOURCES
    )
    if unlisted:
        print(
            "::error::the facade re-exports from "
            + ", ".join(unlisted)
            + ": add them to FACADE_SOURCES in scripts/ci/changes.py",
        )
        return 1

    failed: list[str] = []
    for crate in sorted(set(exposed["current"]) | set(exposed["baseline"])):
        if crate not in packages["current"] or crate == FACADE_CRATE:
            continue  # not a workspace crate (jiff): its own release policy
        package = packages["current"][crate]
        if crate not in packages["baseline"]:
            print(f"::notice::{package} is new in this change: no baseline API to check against")
            continue
        documents: dict[str, Path] = {}
        for side, (root, target) in sides.items():
            # The items the facade exposed at the base stay held at the change:
            # an item the facade stops re-exporting is the facade's own check's.
            kept = exposed["baseline"].get(crate, set()) | exposed[side].get(crate, set())
            doc, missing = prune(rustdoc_json(root, target, package), kept)
            if side == "current" and missing:
                for path in missing:
                    print(f"::notice::{package} no longer defines {'::'.join(path)}")
            documents[side] = work / f"{crate}.{side}.json"
            documents[side].write_text(json.dumps(doc), encoding="utf-8")
        print(f"==> {package}: the API the facade re-exports", flush=True)
        result = subprocess.run(
            [
                "cargo",
                "semver-checks",
                "--current-rustdoc",
                str(documents["current"]),
                "--baseline-rustdoc",
                str(documents["baseline"]),
                "--release-type",
                "minor",
            ],
            check=False,
        )
        if result.returncode != 0:
            failed.append(package)

    if failed:
        print(
            "::error::a breaking change to what the facade re-exports from "
            + ", ".join(failed)
            + ": see crates/opentide/AGENTS.md, Semver",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
