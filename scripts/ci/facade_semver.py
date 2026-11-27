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

Each re-exported item is tracked by its facade path (`plugins::set_host`): an
item that moved between workspace crates is held in the crate that defines it
now, not reported missing from the one that used to (#2040). A facade path
that resolves nowhere any more stays with its old crate, and fails there.

A moved item has no baseline in its new crate, so it is also compared at its
facade path (#1985): its old crate's document at the base and its new crate's
at the change each expose only the moved items, at their facade paths, under
the facade's name, and cargo semver-checks runs on that pair. A signature or
an attribute (`#[non_exhaustive]`) changed in the commit that moves the item
fails there as it would in place.

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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

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


def facade_paths(facade: JsonDoc) -> dict[int, ItemPath]:
    """The facade path of each `use` item public modules reach: ("plugins", "set_host")."""
    index = facade["index"]
    found: dict[int, ItemPath] = {}
    stack: list[tuple[int, ItemPath]] = [(facade["root"], ())]
    seen: set[int] = set()
    while stack:
        item_id, prefix = stack.pop()
        if item_id in seen:
            continue
        seen.add(item_id)
        item = index.get(str(item_id))
        if item is None or "module" not in item["inner"]:
            continue
        for child in item["inner"]["module"]["items"]:
            entry = index.get(str(child))
            if entry is None:
                continue
            use = entry["inner"].get("use")
            if use is not None:
                name = use["name"]
                found[child] = (*prefix, name, "*") if use["is_glob"] else (*prefix, name)
            elif "module" in entry["inner"]:
                stack.append((child, (*prefix, entry["name"])))
    return found


def reexports(facade: JsonDoc) -> dict[ItemPath, tuple[str, ItemPath]]:
    """The items other crates define that the facade re-exports, by facade path.

    Each maps to its defining crate and its canonical path there. A `use` no
    public module reaches is keyed by that crate and path.
    """
    crates = facade["external_crates"]
    paths = facade_paths(facade)
    found: dict[ItemPath, tuple[str, ItemPath]] = {}
    for item_id, item in facade["index"].items():
        use = item["inner"].get("use")
        if use is None or use["id"] is None:
            continue
        summary = facade["paths"].get(str(use["id"]))
        if summary is None or summary["crate_id"] == 0:
            continue
        crate = crates[str(summary["crate_id"])]["name"]
        canonical = tuple(summary["path"][1:])
        key = paths.get(int(item_id), ("<unreached>", crate, *canonical))
        found[key] = (crate, canonical)
    return found


def by_crate(
    exposed: dict[ItemPath, tuple[str, ItemPath]],
    current: dict[ItemPath, tuple[str, ItemPath]] | None = None,
    workspace: set[str] | frozenset[str] = frozenset(),
) -> dict[str, set[ItemPath]]:
    """The items `exposed` names, grouped by the crate they are checked in.

    With `current` (the change's re-exports), an item whose facade path now
    resolves in another workspace crate is held there (#2040): it moved, and
    its old crate no longer promises it. A facade path the change drops stays
    with its old crate, so a removal there still fails.
    """
    found: dict[str, set[ItemPath]] = {}
    for facade_path, (crate, canonical) in exposed.items():
        moved = (current or {}).get(facade_path)
        if moved is not None and moved[0] != crate and moved[0] in workspace:
            crate, canonical = moved
        found.setdefault(crate, set()).add(canonical)
    return found


def moved(
    baseline: dict[ItemPath, tuple[str, ItemPath]],
    current: dict[ItemPath, tuple[str, ItemPath]],
    workspace: set[str] | frozenset[str],
) -> dict[tuple[str, str], dict[ItemPath, tuple[ItemPath, ItemPath]]]:
    """The re-exports whose defining crate changed between two workspace crates.

    Keyed by (old crate, new crate); each facade path maps to its canonical
    path in the old crate and in the new one. These are the items `by_crate`
    holds in their new crate, where the base has no baseline for them.
    """
    found: dict[tuple[str, str], dict[ItemPath, tuple[ItemPath, ItemPath]]] = {}
    for facade_path, (old_crate, old_path) in baseline.items():
        if facade_path[0] == "<unreached>":
            continue
        new = current.get(facade_path)
        if new is None or new[0] == old_crate or not {old_crate, new[0]} <= set(workspace):
            continue
        found.setdefault((old_crate, new[0]), {})[facade_path] = (old_path, new[1])
    return found


def facade_view(doc: JsonDoc, items: dict[ItemPath, ItemPath]) -> tuple[JsonDoc, list[ItemPath]]:
    """`doc` exposing only `items` (facade path to canonical path), at their facade paths.

    The root takes the facade's name and holds one module per facade module,
    each with a `use` of its items, so two crates' documents compare item for
    item at the paths a caller writes. Returns the document and the facade
    paths whose item `doc` does not define.
    """
    index = doc["index"]
    by_path = {
        tuple(summary["path"][1:]): int(item_id)
        for item_id, summary in doc["paths"].items()
        if summary["crate_id"] == 0
    }
    root = index[str(doc["root"])]
    next_id = max(int(item_id) for item_id in index) + 1
    modules: dict[ItemPath, JsonDoc] = {(): root}
    root["name"] = FACADE_CRATE
    root["inner"]["module"]["items"] = []

    def new_item(name: str | None, inner: JsonDoc) -> int:
        nonlocal next_id
        item_id = next_id
        next_id += 1
        entry = {key: value for key, value in root.items() if key != "inner"}
        entry.update(id=item_id, name=name, inner=inner, docs=None, links={}, attrs=[])
        index[str(item_id)] = entry
        return item_id

    def module(prefix: ItemPath) -> JsonDoc:
        if prefix not in modules:
            parent = module(prefix[:-1])
            item_id = new_item(
                prefix[-1], {"module": {"is_crate": False, "items": [], "is_stripped": False}}
            )
            parent["inner"]["module"]["items"].append(item_id)
            modules[prefix] = index[str(item_id)]
        return modules[prefix]

    missing: list[ItemPath] = []
    for facade_path, canonical in sorted(items.items()):
        target = by_path.get(canonical)
        if target is None:
            missing.append(facade_path)
            continue
        is_glob = facade_path[-1] == "*"
        parent = module(facade_path[:-2] if is_glob else facade_path[:-1])
        name = canonical[-1] if is_glob else facade_path[-1]
        use = {"source": "::".join(canonical), "name": name, "id": target, "is_glob": is_glob}
        parent["inner"]["module"]["items"].append(new_item(None, {"use": use}))
    return doc, missing


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


def prune(
    doc: JsonDoc,
    kept: set[ItemPath],
    foreign: set[tuple[str, ItemPath]] | None = None,
) -> tuple[JsonDoc, list[ItemPath]]:
    """`doc` with only the public paths that lead to the `kept` items.

    Returns the pruned document and the kept paths it does not define. With
    `foreign`, adds to it each type of another crate that what is kept names
    (its crate and its canonical path there), as `(crate, path)`.
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
            elif named not in local and foreign is not None:
                summary = doc["paths"].get(str(named))
                if summary is not None and summary["crate_id"] != 0:
                    crate = doc["external_crates"][str(summary["crate_id"])]["name"]
                    foreign.add((crate, tuple(summary["path"][1:])))
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


def close_over(
    exposed: dict[str, set[ItemPath]],
    packages: dict[str, str],
    document: Callable[[str], JsonDoc],
) -> None:
    """Add to `exposed` the types of other workspace crates its items name, until none is new.

    `packages` maps the side's crate names to package names and `document`
    builds a package's rustdoc JSON on that side. A crate the side does not
    have (an item `by_crate` moved to a crate new in the change) is skipped.
    """
    pending = sorted(crate for crate in exposed if crate in packages)
    while pending:
        crate = pending.pop()
        if crate == FACADE_CRATE:
            continue
        foreign: set[tuple[str, ItemPath]] = set()
        prune(document(packages[crate]), set(exposed[crate]), foreign)
        for named_crate, path in sorted(foreign):
            if named_crate not in packages or named_crate == FACADE_CRATE:
                continue
            held = exposed.setdefault(named_crate, set())
            if path not in held:
                held.add(path)
                if named_crate not in pending:
                    pending.append(named_crate)


def semver_checks(current: Path, baseline: Path) -> bool:
    """Whether cargo semver-checks finds no major change from `baseline` to `current`."""
    result = subprocess.run(
        [
            "cargo",
            "semver-checks",
            "--current-rustdoc",
            str(current),
            "--baseline-rustdoc",
            str(baseline),
            "--release-type",
            "minor",
        ],
        check=False,
    )
    return result.returncode == 0


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
    found = {
        side: reexports(rustdoc_json(root, target, FACADE))
        for side, (root, target) in sides.items()
    }
    packages = {side: workspace_packages(root) for side, (root, _) in sides.items()}
    # Each item is tracked by its facade path: one that moved between
    # workspace crates is held in the crate that defines it now.
    exposed = {
        "current": by_crate(found["current"]),
        "baseline": by_crate(found["baseline"], found["current"], set(packages["current"])),
    }
    # The types of other workspace crates that a re-exported item names (a
    # field's, a parameter's) are the facade's API too, though the facade
    # never names them: they are held in their own crates, on each side from
    # that side's documents (#1985). The base's closure is what the change is
    # held to: computed from the change alone, a foreign type the facade
    # exposed only through another crate would have no baseline, and any
    # break to it would read as an addition.
    for side, (root, target) in sides.items():
        close_over(
            exposed[side],
            packages[side],
            lambda package, root=root, target=target: rustdoc_json(root, target, package),
        )

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
            # The items the facade exposed at the base, directly or through a
            # re-exported item's types, stay held at the change: an item the
            # facade stops re-exporting is the facade's own check's.
            kept = exposed["baseline"].get(crate, set()) | exposed[side].get(crate, set())
            doc, missing = prune(rustdoc_json(root, target, package), kept)
            if side == "current" and missing:
                for path in missing:
                    print(f"::notice::{package} no longer defines {'::'.join(path)}")
            documents[side] = work / f"{crate}.{side}.json"
            documents[side].write_text(json.dumps(doc), encoding="utf-8")
        print(f"==> {package}: the API the facade re-exports", flush=True)
        if not semver_checks(documents["current"], documents["baseline"]):
            failed.append(package)

    # A moved item, at its facade path: the old crate at the base against the
    # new crate at the change (#1985).
    for (old, new), items in sorted(
        moved(
            found["baseline"],
            found["current"],
            set(packages["baseline"]) | set(packages["current"]),
        ).items()
    ):
        if old not in packages["baseline"]:
            continue
        label = f"{packages['baseline'][old]} -> {packages['current'][new]}"
        documents = {}
        for side, crate, which in (("baseline", old, 0), ("current", new, 1)):
            root, target = sides[side]
            view = {facade_path: paths[which] for facade_path, paths in items.items()}
            doc, missing = facade_view(rustdoc_json(root, target, packages[side][crate]), view)
            for path in missing:
                print(
                    f"::notice::{label}: {packages[side][crate]} does not define {'::'.join(path)}"
                )
            documents[side] = work / f"moved.{old}.{new}.{side}.json"
            documents[side].write_text(json.dumps(doc), encoding="utf-8")
        print(f"==> {label}: the items that moved, at their facade paths", flush=True)
        if not semver_checks(documents["current"], documents["baseline"]):
            failed.append(label)

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
