#!/usr/bin/env python3
"""One-shot migration: vocabulary YAML → {field}.vocab.toml with id cleanup."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from opentide.core.root import get_data_root
from opentide.generation.vocabulary import resolve_vocab_key
from opentide.vocabulary.io import strip_spurious_entry_id, write_vocab_file

ID_KEYED_FIELDS = frozenset({"att&ck", "att&ck.groups", "actors", "nist", "indicators"})


def _yaml_to_document(raw: dict, *, field: str) -> dict:
    doc = {k: v for k, v in raw.items() if k != "keys"}
    doc["field"] = field

    if raw.get("model") or field in ID_KEYED_FIELDS:
        doc["key"] = "id"
    else:
        doc["key"] = "name"
    doc.pop("model", None)

    vocab_key = resolve_vocab_key(doc)
    keys: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for entry in raw.get("keys") or []:
        if not isinstance(entry, dict):
            continue
        cleaned = strip_spurious_entry_id(entry, vocab_key=vocab_key, field=field)
        if "name" not in cleaned:
            continue
        cleaned = {k: v for k, v in cleaned.items() if v is not None}
        if vocab_key == "id":
            dedupe_key = ("id", str(cleaned.get("id", "")))
        else:
            dedupe_key = ("name", str(cleaned["name"]))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        keys.append(cleaned)

    doc["keys"] = keys
    return doc


def migrate_vocabulary_dir(vocab_dir: Path, *, delete_yaml: bool = False) -> int:
    count = 0
    for yaml_path in sorted(vocab_dir.glob("*.yaml")):
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        if not raw:
            print(f"SKIP empty: {yaml_path.name}", file=sys.stderr)
            continue
        field = str(raw.get("field", ""))
        if not field:
            print(f"SKIP no field: {yaml_path.name}", file=sys.stderr)
            continue

        document = _yaml_to_document(raw, field=field)
        dest = vocab_dir / f"{field}.vocab.toml"
        write_vocab_file(dest, document)
        print(f"Wrote {dest.name}")
        count += 1

        if delete_yaml:
            yaml_path.unlink()
            print(f"Deleted {yaml_path.name}")

    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate vocabulary YAML to TOML")
    parser.add_argument(
        "--vocab-dir",
        type=Path,
        default=get_data_root() / "vocabulary",
    )
    parser.add_argument("--delete-yaml", action="store_true")
    args = parser.parse_args()
    migrated = migrate_vocabulary_dir(args.vocab_dir, delete_yaml=args.delete_yaml)
    print(f"Migrated {migrated} vocabulary file(s)")


if __name__ == "__main__":
    main()
