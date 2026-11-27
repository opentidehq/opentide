"""scripts/ci/facade_semver.py: the facade's re-exports, checked in their crates (#1911).

cargo semver-checks never sees an item the facade re-exports from another
crate. The script finds those items in the facade's rustdoc JSON and keeps,
in each defining crate's JSON, only what the facade exposes. The documents
here are synthetic, in rustdoc JSON's shape (format 50 and later).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

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
    assert facade_semver.reexports(facade) == {"opentide_core": {("LanguageId",), ("codes",)}}


def test_only_what_the_facade_exposes_is_kept() -> None:
    doc, missing = facade_semver.prune(core(), {("LanguageId",), ("Request",), ("codes",)})
    assert missing == []
    # Request names Detail in a field: the `use` that makes it public stays.
    assert root_items(doc) == {"LanguageId", "Request", "Detail", "codes"}
    # A re-exported module keeps all of its items.
    assert doc["index"]["5"]["inner"]["module"]["items"] == [6]


def test_an_item_the_crate_no_longer_defines_is_reported() -> None:
    doc, missing = facade_semver.prune(core(), {("LanguageId",), ("Gone",)})
    assert missing == [("Gone",)]
    assert root_items(doc) == {"LanguageId"}
