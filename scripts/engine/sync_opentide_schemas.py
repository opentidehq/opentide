#!/usr/bin/env python3
"""Generate the Tide catalogs compiled into the engine, with opentide's own generator.

opentide is the authority on Tide objects, and ``opentide.generation.lsp_catalog``
is the one generator of the language server's field catalog: ``opentide generate
schemas`` runs it to write a workspace's catalogs, and this script runs it to
write the bundled ones. It writes:

- ``catalogs/tide/generated/fields.json`` and ``deprecations.json``: one row per
  field per schema revision (``rule::1.0``, ``rule::1.1``), with required and
  closed (no extra keys) flags, so each object is checked against its revision;
- ``catalogs/tide/schemas/*.schema.json``: each revision's JSON Schema, for
  reference (vocabulary essays shortened), and the ``opentide.schema.json``
  router;
- ``highlights/queries/tide/highlights.scm``: the key list of the static query.

Run it with a Python that has opentide installed: a release that ships the
generator, or an opentide checkout (``uv run --project ../opentide python
scripts/sync_opentide_schemas.py``)::

    python3 scripts/sync_opentide_schemas.py           # write
    python3 scripts/sync_opentide_schemas.py --check   # exit 1 when anything would change
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    import opentide
    from opentide.generation import lsp_catalog
except ImportError as exc:  # pragma: no cover - environment
    raise SystemExit(
        f"error: this needs opentide with opentide.generation.lsp_catalog ({exc}).\n"
        "  help: run it with an opentide checkout: "
        "uv run --project ../opentide python scripts/sync_opentide_schemas.py"
    ) from exc

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "catalogs" / "tide" / "schemas"
GENERATED = ROOT / "catalogs" / "tide" / "generated"
HIGHLIGHTS = ROOT / "highlights" / "queries" / "tide" / "highlights.scm"

# Vocabulary essays (ATT&CK, actors) dominate the reference schemas: keep every
# enum value, short docs only for small enums (the catalog does the same).
DOC_CAP = lsp_catalog.DOC_CAP
ENUM_DOC_MAX = lsp_catalog.ENUM_DOC_MAX


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="compare instead of writing; exit 1 on a difference"
    )
    args = parser.parse_args(argv)
    outputs = expected_outputs()
    if args.check:
        return check(outputs)
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    for stale in sorted(SCHEMA_DIR.glob("*.schema.json")):
        if stale not in outputs:
            stale.unlink()
            print(f"removed {stale.relative_to(ROOT)} (not registered in opentide {opentide.__version__})")
    return 0


def expected_outputs() -> dict[Path, str]:
    """Every file this script writes, with its content."""
    from opentide.generation.pydantic_schemas import generate_schema_for_identifier
    from opentide.models.object_types import CORE_OBJECT_TYPES
    from opentide.models.schema_registry import identifiers_for_families

    outputs: dict[Path, str] = {}
    catalogs = lsp_catalog.catalog_texts()
    for name, text in catalogs.items():
        outputs[GENERATED / name] = text
    schema_ids = list(identifiers_for_families(CORE_OBJECT_TYPES))
    for schema_id in schema_ids:
        family, revision = schema_id.split("::", 1)
        schema = generate_schema_for_identifier(schema_id)
        outputs[SCHEMA_DIR / f"{family}.{revision}.schema.json"] = dump_schema(schema)
    outputs[SCHEMA_DIR / "opentide.schema.json"] = dump_schema(router(schema_ids))
    fields = json.loads(catalogs[lsp_catalog.FIELDS_FILE])["fields"]
    outputs[HIGHLIGHTS] = highlights(fields)
    return outputs


def check(outputs: dict[Path, str]) -> int:
    """Whether the committed files match what opentide generates, labels aside."""
    problems: list[str] = []
    found = {
        name: (GENERATED / name).read_text(encoding="utf-8") if (GENERATED / name).is_file() else None
        for name in (lsp_catalog.FIELDS_FILE, lsp_catalog.DEPRECATIONS_FILE)
    }
    expected = {name: outputs[GENERATED / name] for name in found}
    for name, difference in lsp_catalog.catalog_differences(expected, found):
        problems.append(f"catalogs/tide/generated/{name}: {difference}")
    for path, text in outputs.items():
        if path.parent == GENERATED:
            continue
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if _unlabelled(path, current) != _unlabelled(path, text):
            problems.append(f"{path.relative_to(ROOT)}: differs")
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if problems:
        print(
            f"opentide {opentide.__version__} generates different catalogs: "
            "run python3 scripts/sync_opentide_schemas.py",
            file=sys.stderr,
        )
        return 1
    print(f"the catalogs match opentide {opentide.__version__}")
    return 0


def _unlabelled(path: Path, text: str | None) -> str | None:
    """*text* without the line that names the opentide version it came from."""
    if text is None:
        return None
    marker = "Generated from opentide " if path.suffix == ".json" else "; (opentide "
    return "\n".join(line for line in text.splitlines() if marker not in line)


def dump_schema(schema: dict[str, Any]) -> str:
    """Stable JSON. Shorten vocab essays; keep enum values, titles, $defs."""
    return json.dumps(shorten_enum_docs(schema), indent=2) + "\n"


def shorten_enum_docs(node: Any) -> Any:
    if isinstance(node, dict):
        enum = node.get("enum")
        drop_docs = isinstance(enum, list) and len(enum) > ENUM_DOC_MAX
        out = {}
        for key, value in node.items():
            if key == "markdownEnumDescriptions":
                if drop_docs or not isinstance(value, list):
                    continue
                out[key] = [cap_doc(short_doc(v)) if isinstance(v, str) else v for v in value]
            else:
                out[key] = shorten_enum_docs(value)
        return out
    if isinstance(node, list):
        return [shorten_enum_docs(v) for v in node]
    return node


def short_doc(markdown: str) -> str:
    text = markdown.strip()
    if "---" in text:
        text = text.split("---")[-1].strip()
    return " ".join(text.split())


def cap_doc(text: str) -> str:
    if len(text) <= DOC_CAP:
        return text
    return text[: DOC_CAP - 1].rstrip() + "…"


def router(schema_ids: list[str]) -> dict[str, Any]:
    """One schema that picks a revision's schema by ``metadata.schema``."""
    branches = []
    for schema_id in schema_ids:
        family, revision = schema_id.split("::", 1)
        branches.append(
            {
                "if": {
                    "properties": {
                        "metadata": {
                            "properties": {"schema": {"const": schema_id}},
                            "required": ["schema"],
                        }
                    },
                    "required": ["metadata"],
                },
                "then": {"$ref": f"./{family}.{revision}.schema.json"},
            }
        )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://opentide.dev/schemas/opentide.schema.json",
        "title": "opentide Object Router",
        "description": f"Generated from opentide {opentide.__version__}.",
        "oneOf": branches,
    }


def highlights(fields: list[dict[str, Any]]) -> str:
    groups = [
        ("tide.property", sorted({f["name"] for f in fields if f["capture"] == "tide.property"})),
        ("tide.keyword", sorted({f["name"] for f in fields if f["capture"] == "tide.keyword"})),
    ]
    queries = []
    for capture, names in groups:
        if not names:
            continue
        queries.append(
            f"""\
((block_mapping_pair
  key: (_) @{capture})
 (#match? @{capture} "^({alt(names)})$"))
"""
        )
    return f"""\
; Tide YAML object highlighting. Injected KQL/SPL tokens are remapped onto
; the host document by opentide-highlight (not by this query).
; Generated key lists come from catalogs/tide/generated/fields.json
; (opentide {opentide.__version__}). Runtime highlighting is path-aware and does not
; use this query. Every schema key uses tide.property so nesting does not
; recolor the key. Capture names must stay a subset of HighlightSpec.

{''.join(queries)}
(comment) @comment
"""


def alt(names: list[str]) -> str:
    # Only regex metacharacters. `re.escape` also escapes `&` (`att&ck`).
    meta = set(".^$*+?()[]{}|\\")

    def esc(name: str) -> str:
        return "".join(f"\\{char}" if char in meta else char for char in name)

    return "|".join(esc(name) for name in names)


if __name__ == "__main__":
    raise SystemExit(main())
