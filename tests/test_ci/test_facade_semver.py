"""scripts/ci/facade_semver.py: the facade's re-exports, checked in their crates (#1911).

cargo semver-checks never sees an item the facade re-exports from another
crate. The script finds those items in the facade's rustdoc JSON and keeps,
in each defining crate's JSON, only what the facade exposes. The documents
here are synthetic, in rustdoc JSON's shape (format 50 and later).
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "facade_semver", Path(__file__).resolve().parents[2] / "scripts" / "ci" / "facade_semver.py"
)
assert _SPEC is not None and _SPEC.loader is not None
facade_semver: ModuleType = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(facade_semver)


def item(name: str | None, inner: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "inner": inner}


def module(name: str | None, items: list[int], *, is_crate: bool = False) -> dict[str, Any]:
    return item(name, {"module": {"is_crate": is_crate, "items": items, "is_stripped": False}})


def struct(name: str, fields: list[int]) -> dict[str, Any]:
    return item(
        name,
        {
            "struct": {
                "kind": {"plain": {"fields": fields, "has_stripped_fields": False}},
                "generics": {"params": [], "where_predicates": []},
                "impls": [],
            }
        },
    )


def field(name: str, type_id: int | None) -> dict[str, Any]:
    if type_id is None:
        return item(name, {"struct_field": {"primitive": "bool"}})
    return item(
        name, {"struct_field": {"resolved_path": {"path": "X", "id": type_id, "args": None}}}
    )


def core() -> dict[str, Any]:
    """`opentide_core`, as a crate the facade re-exports from.

    lib.rs: `pub enum LanguageId`, `pub struct Request { pub detail: Detail }`
    (`Detail` defined in the private module `detail`, re-exported at the
    root), `pub mod codes { pub const A }` and `pub fn internal()`, which the
    facade does not re-export.
    """
    index = {
        "0": module("opentide_core", [1, 2, 3, 5, 7, 9], is_crate=True),
        "1": item("LanguageId", {"enum": {"variants": [], "impls": []}}),
        "2": struct("Request", [10]),
        "10": field("detail", 4),
        "3": item(
            None, {"use": {"source": "detail::Detail", "name": "Detail", "id": 4, "is_glob": False}}
        ),
        "4": struct("Detail", [11]),
        "11": field("flag", None),
        "5": module("codes", [6]),
        "6": item("A", {"constant": {"type": {"primitive": "str"}}}),
        "7": item("internal", {"function": {}}),
        "9": struct("Unrelated", []),
    }
    paths = {
        "0": {"crate_id": 0, "path": ["opentide_core"], "kind": "module"},
        "1": {"crate_id": 0, "path": ["opentide_core", "LanguageId"], "kind": "enum"},
        "2": {"crate_id": 0, "path": ["opentide_core", "Request"], "kind": "struct"},
        "4": {"crate_id": 0, "path": ["opentide_core", "detail", "Detail"], "kind": "struct"},
        "5": {"crate_id": 0, "path": ["opentide_core", "codes"], "kind": "module"},
        "6": {"crate_id": 0, "path": ["opentide_core", "codes", "A"], "kind": "constant"},
        "7": {"crate_id": 0, "path": ["opentide_core", "internal"], "kind": "function"},
        "9": {"crate_id": 0, "path": ["opentide_core", "Unrelated"], "kind": "struct"},
    }
    return {"root": 0, "index": index, "paths": paths, "external_crates": {}}


def root_items(doc: dict[str, Any]) -> set[str]:
    index = doc["index"]
    names = set()
    for child in index[str(doc["root"])]["inner"]["module"]["items"]:
        entry = index[str(child)]
        names.add(entry["name"] or entry["inner"]["use"]["name"])
    return names


def test_the_facade_re_exports_are_found_by_their_defining_crate() -> None:
    facade = {
        "root": 0,
        "index": {
            "0": module("opentide", [1, 2, 3], is_crate=True),
            # `pub use opentide_analysis::LanguageId;`: opentide_analysis
            # re-exports it from opentide_core, its canonical path.
            "1": item(
                None,
                {
                    "use": {
                        "source": "opentide_analysis::LanguageId",
                        "name": "LanguageId",
                        "id": 20,
                        "is_glob": False,
                    }
                },
            ),
            "2": item(
                None,
                {
                    "use": {
                        "source": "opentide_core::codes",
                        "name": "codes",
                        "id": 21,
                        "is_glob": False,
                    }
                },
            ),
            # The facade's own item, and a `use` of something unresolved.
            "3": item(
                None, {"use": {"source": "self::x", "name": "x", "id": None, "is_glob": False}}
            ),
        },
        "paths": {
            "20": {"crate_id": 7, "path": ["opentide_core", "LanguageId"], "kind": "enum"},
            "21": {"crate_id": 7, "path": ["opentide_core", "codes"], "kind": "module"},
        },
        "external_crates": {"7": {"name": "opentide_core"}},
    }
    found = facade_semver.reexports(facade)
    assert found == {
        ("LanguageId",): ("opentide_core", ("LanguageId",)),
        ("codes",): ("opentide_core", ("codes",)),
    }
    assert facade_semver.by_crate(found) == {"opentide_core": {("LanguageId",), ("codes",)}}


def test_only_what_the_facade_exposes_is_kept() -> None:
    doc, missing = facade_semver.prune(core(), {("LanguageId",), ("Request",), ("codes",)})
    assert missing == []
    # Request names Detail in a field: the `use` that makes it public stays.
    assert root_items(doc) == {"LanguageId", "Request", "Detail", "codes"}
    # A re-exported module keeps all of its items.
    assert doc["index"]["5"]["inner"]["module"]["items"] == [6]


def test_the_types_of_other_crates_that_kept_items_name_are_collected() -> None:
    doc = core()
    # `Detail` gains a field typed by another crate's `Pin`; `Unrelated`,
    # which the facade does not re-export, one typed by its `Other`.
    doc["index"]["4"] = struct("Detail", [11, 12])
    doc["index"]["12"] = field("pin", 50)
    doc["index"]["9"] = struct("Unrelated", [13])
    doc["index"]["13"] = field("other", 51)
    doc["paths"]["50"] = {"crate_id": 3, "path": ["opentide_dataset", "pins", "Pin"]}
    doc["paths"]["51"] = {"crate_id": 3, "path": ["opentide_dataset", "Other"]}
    doc["external_crates"] = {"3": {"name": "opentide_dataset"}}
    foreign: set[tuple[str, tuple[str, ...]]] = set()
    facade_semver.prune(doc, {("Request",)}, foreign)
    # Through `Request.detail`, a type the crate defines: followed in turn.
    assert foreign == {("opentide_dataset", ("pins", "Pin"))}


def test_an_item_the_crate_no_longer_defines_is_reported() -> None:
    doc, missing = facade_semver.prune(core(), {("LanguageId",), ("Gone",)})
    assert missing == [("Gone",)]
    assert root_items(doc) == {"LanguageId"}


def plugins_facade(crate: str, path: list[str]) -> dict[str, Any]:
    """The facade's `pub mod plugins { pub use <crate>::<path>::set_host; }`."""
    return {
        "root": 0,
        "index": {
            "0": module("opentide", [1], is_crate=True),
            "1": module("plugins", [2]),
            "2": item(
                None,
                {
                    "use": {
                        "source": "::".join([crate, *path]),
                        "name": path[-1],
                        "id": 30,
                        "is_glob": False,
                    }
                },
            ),
        },
        "paths": {"30": {"crate_id": 4, "path": [crate, *path], "kind": "function"}},
        "external_crates": {"4": {"name": crate}},
    }


def cli(*, defines: bool) -> dict[str, Any]:
    """`opentide_cli`: `pub mod plugins { pub fn set_host() }`, or no `set_host`."""
    index = {
        "0": module("opentide_cli", [1], is_crate=True),
        "1": module("plugins", [2] if defines else []),
    }
    paths = {
        "0": {"crate_id": 0, "path": ["opentide_cli"], "kind": "module"},
        "1": {"crate_id": 0, "path": ["opentide_cli", "plugins"], "kind": "module"},
    }
    if defines:
        index["2"] = item("set_host", {"function": {}})
        paths["2"] = {"crate_id": 0, "path": ["opentide_cli", "plugins", "set_host"]}
    return {"root": 0, "index": index, "paths": paths, "external_crates": {}}


WORKSPACE = {"opentide_cli", "opentide_connectors"}


def test_an_item_that_moved_between_workspace_crates_is_held_in_its_new_crate() -> None:
    baseline = facade_semver.reexports(plugins_facade("opentide_cli", ["plugins", "set_host"]))
    current = facade_semver.reexports(
        plugins_facade("opentide_connectors", ["plugin", "host", "set_host"])
    )
    # One facade path, two defining crates.
    assert set(baseline) == set(current) == {("plugins", "set_host")}
    held = facade_semver.by_crate(baseline, current, WORKSPACE)
    assert held == {"opentide_connectors": {("plugin", "host", "set_host")}}
    # The old crate holds nothing: its change no longer defining the item is no failure.
    _, missing = facade_semver.prune(cli(defines=False), held.get("opentide_cli", set()))
    assert missing == []


def test_an_item_removed_at_its_facade_path_is_still_held_in_its_old_crate() -> None:
    baseline = facade_semver.reexports(plugins_facade("opentide_cli", ["plugins", "set_host"]))
    # The change drops the re-export and the function: no new crate takes it.
    current = facade_semver.reexports(
        {"root": 0, "index": {"0": module("opentide", [], is_crate=True)}, "paths": {}}
        | {"external_crates": {}}
    )
    held = facade_semver.by_crate(baseline, current, WORKSPACE)
    assert held == {"opentide_cli": {("plugins", "set_host")}}
    # The baseline keeps the function and the change does not define it:
    # cargo semver-checks reads that pair as function_missing.
    doc, missing = facade_semver.prune(cli(defines=True), held["opentide_cli"])
    assert missing == []
    assert doc["index"]["1"]["inner"]["module"]["items"] == [2]
    _, missing = facade_semver.prune(cli(defines=False), held["opentide_cli"])
    assert missing == [("plugins", "set_host")]


def test_an_item_moved_to_a_crate_outside_the_workspace_stays_in_its_old_crate() -> None:
    baseline = facade_semver.reexports(plugins_facade("opentide_cli", ["plugins", "set_host"]))
    current = facade_semver.reexports(plugins_facade("jiff", ["set_host"]))
    held = facade_semver.by_crate(baseline, current, WORKSPACE)
    assert held == {"opentide_cli": {("plugins", "set_host")}}


def test_a_moved_item_is_paired_from_its_old_crate_to_its_new_one() -> None:
    baseline = facade_semver.reexports(plugins_facade("opentide_cli", ["plugins", "set_host"]))
    current = facade_semver.reexports(
        plugins_facade("opentide_connectors", ["plugin", "host", "set_host"])
    )
    assert facade_semver.moved(baseline, current, WORKSPACE) == {
        ("opentide_cli", "opentide_connectors"): {
            ("plugins", "set_host"): (("plugins", "set_host"), ("plugin", "host", "set_host"))
        }
    }
    # Not moved: the same crate, a crate outside the workspace, or dropped.
    assert facade_semver.moved(baseline, baseline, WORKSPACE) == {}
    jiff = facade_semver.reexports(plugins_facade("jiff", ["set_host"]))
    assert facade_semver.moved(baseline, jiff, WORKSPACE) == {}
    assert facade_semver.moved(baseline, {}, WORKSPACE) == {}


def connectors() -> dict[str, Any]:
    """`opentide_connectors`: `pub mod plugin { pub mod host { pub fn set_host() } }`."""
    index = {
        "0": module("opentide_connectors", [1, 4], is_crate=True),
        "1": module("plugin", [2]),
        "2": module("host", [3]),
        "3": item("set_host", {"function": {}}),
        "4": item("internal", {"function": {}}),
    }
    paths = {
        "0": {"crate_id": 0, "path": ["opentide_connectors"], "kind": "module"},
        "3": {"crate_id": 0, "path": ["opentide_connectors", "plugin", "host", "set_host"]},
        "4": {"crate_id": 0, "path": ["opentide_connectors", "internal"]},
    }
    return {"root": 0, "index": index, "paths": paths, "external_crates": {}}


def test_a_moved_item_is_exposed_at_its_facade_path_in_either_crate() -> None:
    for doc, canonical in (
        (cli(defines=True), ("plugins", "set_host")),
        (connectors(), ("plugin", "host", "set_host")),
    ):
        view, missing = facade_semver.facade_view(doc, {("plugins", "set_host"): canonical})
        assert missing == []
        index = view["index"]
        root = index[str(view["root"])]
        # The root is the facade's and holds `plugins` alone: the crate's own
        # modules and its other items are out of reach.
        assert root["name"] == "opentide"
        [plugins] = [index[str(child)] for child in root["inner"]["module"]["items"]]
        assert plugins["name"] == "plugins"
        [use] = [index[str(child)]["inner"]["use"] for child in plugins["inner"]["module"]["items"]]
        assert use["name"] == "set_host"
        assert index[str(use["id"])]["name"] == "set_host"


def test_a_moved_item_its_crate_does_not_define_is_reported() -> None:
    view = {("plugins", "set_host"): ("plugins", "set_host")}
    _, missing = facade_semver.facade_view(cli(defines=False), view)
    assert missing == [("plugins", "set_host")]


def analysis() -> dict[str, Any]:
    """`opentide_analysis`: `pub struct Tree { pub root: opentide_core::node::Node }`."""
    index = {
        "0": module("opentide_analysis", [1], is_crate=True),
        "1": struct("Tree", [2]),
        "2": field("root", 40),
    }
    paths = {
        "0": {"crate_id": 0, "path": ["opentide_analysis"], "kind": "module"},
        "1": {"crate_id": 0, "path": ["opentide_analysis", "Tree"], "kind": "struct"},
        "40": {"crate_id": 2, "path": ["opentide_core", "node", "Node"], "kind": "struct"},
    }
    return {
        "root": 0,
        "index": index,
        "paths": paths,
        "external_crates": {"2": {"name": "opentide_core"}},
    }


def node_core(fields: list[str], *, non_exhaustive: bool = False) -> dict[str, Any]:
    """`opentide_core`: `pub mod node { pub struct Node { <fields> } }`, and `pub fn internal()`."""
    field_ids = list(range(10, 10 + len(fields)))
    index = {
        "0": module("opentide_core", [1, 3], is_crate=True),
        "1": module("node", [2]),
        "2": struct("Node", field_ids),
        "3": item("internal", {"function": {}}),
    }
    if non_exhaustive:
        index["2"]["attrs"] = ["non_exhaustive"]
    for field_id, name in zip(field_ids, fields, strict=True):
        index[str(field_id)] = field(name, None)
    paths = {
        "0": {"crate_id": 0, "path": ["opentide_core"], "kind": "module"},
        "1": {"crate_id": 0, "path": ["opentide_core", "node"], "kind": "module"},
        "2": {"crate_id": 0, "path": ["opentide_core", "node", "Node"], "kind": "struct"},
        "3": {"crate_id": 0, "path": ["opentide_core", "internal"], "kind": "function"},
    }
    return {"root": 0, "index": index, "paths": paths, "external_crates": {}}


def tree_facade() -> dict[str, Any]:
    """The facade's `pub use opentide_analysis::Tree;`: nothing from opentide_core."""
    return {
        "root": 0,
        "index": {
            "0": module("opentide", [1], is_crate=True),
            "1": item(
                None,
                {
                    "use": {
                        "source": "opentide_analysis::Tree",
                        "name": "Tree",
                        "id": 30,
                        "is_glob": False,
                    }
                },
            ),
        },
        "paths": {"30": {"crate_id": 5, "path": ["opentide_analysis", "Tree"], "kind": "struct"}},
        "external_crates": {"5": {"name": "opentide_analysis"}},
    }


def public_structs(doc: dict[str, Any]) -> dict[tuple[str, ...], tuple[set[str], bool]]:
    """Each struct a public path reaches: its fields and whether it is `#[non_exhaustive]`."""
    index = doc["index"]
    by_id = {int(key): tuple(summary["path"][1:]) for key, summary in doc["paths"].items()}
    found: dict[tuple[str, ...], tuple[set[str], bool]] = {}
    stack = [doc["root"]]
    while stack:
        entry = index.get(str(stack.pop()))
        if entry is None:
            continue
        inner = entry["inner"]
        if "module" in inner:
            stack.extend(inner["module"]["items"])
        elif "use" in inner and inner["use"]["id"] is not None:
            stack.append(inner["use"]["id"])
        elif "struct" in inner:
            [path] = [path for item_id, path in by_id.items() if index.get(str(item_id)) is entry]
            fields = inner["struct"]["kind"]["plain"]["fields"]
            found[path] = (
                {index[str(child)]["name"] for child in fields},
                "non_exhaustive" in entry.get("attrs", []),
            )
    return found


def fake_semver_checks(current: Path, baseline: Path) -> bool:
    """cargo semver-checks, reduced to two lints.

    A public field removed, and `#[non_exhaustive]` added.
    """
    old = public_structs(json.loads(baseline.read_text(encoding="utf-8")))
    new = public_structs(json.loads(current.read_text(encoding="utf-8")))
    for path, (fields, non_exhaustive) in old.items():
        if path not in new:
            return False
        new_fields, new_non_exhaustive = new[path]
        if not fields <= new_fields or (new_non_exhaustive and not non_exhaustive):
            return False
    return True


def run_main(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, current_core: dict[str, Any]) -> int:
    """`main()`'s exit code on two trees.

    opentide_core goes from `node_core(["kind", "text"])` to `current_core`.
    """
    base, change = tmp_path / "base", tmp_path / "change"
    trees = {
        base: {"opentide": tree_facade(), "opentide-analysis": analysis()}
        | {"opentide-core": node_core(["kind", "text"])},
        change: {"opentide": tree_facade(), "opentide-analysis": analysis()}
        | {"opentide-core": current_core},
    }

    def rustdoc_json(root: Path, _target: Path, package: str) -> dict[str, Any]:
        return copy.deepcopy(trees[root][package])

    packages = {
        "opentide": "opentide",
        "opentide_analysis": "opentide-analysis",
        "opentide_core": "opentide-core",
    }
    monkeypatch.setattr(facade_semver, "rustdoc_json", rustdoc_json)
    monkeypatch.setattr(facade_semver, "workspace_packages", lambda _root: dict(packages))
    monkeypatch.setattr(facade_semver, "semver_checks", fake_semver_checks)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "facade_semver.py",
            "--baseline-root",
            str(base),
            "--current-root",
            str(change),
            "--work-dir",
            str(tmp_path / "work"),
        ],
    )
    return facade_semver.main()


def test_a_break_to_a_foreign_type_a_re_exported_item_names_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The facade re-exports nothing from opentide_core: `Node` is its API only
    # through `Tree.root`, so the base must hold it as well as the change.
    assert run_main(monkeypatch, tmp_path, node_core(["kind"])) == 1
    baseline = public_structs(
        json.loads((tmp_path / "work" / "opentide_core.baseline.json").read_text("utf-8"))
    )
    assert baseline == {("node", "Node"): ({"kind", "text"}, False)}


def test_a_foreign_type_turned_non_exhaustive_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert run_main(monkeypatch, tmp_path, node_core(["kind", "text"], non_exhaustive=True)) == 1


def test_an_unchanged_foreign_type_passes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert run_main(monkeypatch, tmp_path, node_core(["kind", "text"])) == 0
    # A field added is no break.
    assert run_main(monkeypatch, tmp_path, node_core(["kind", "text", "span"])) == 0
