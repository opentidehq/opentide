"""Object vocabulary generation — inline replacement for objects_indexer."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from opentide.core.index_manager import IndexManager


def _empty_model_vocabulary(
    object_type: str, icons: dict[str, str], names: dict[str, str]
) -> dict[str, Any]:
    index_name = names[object_type]
    return {
        "metadata": {
            "field": object_type,
            "icon": icons.get(object_type, ""),
            "name": index_name,
            "description": index_name,
            "model": True,
        },
        "entries": {},
    }


def build_object_vocabularies(
    *,
    object_scope: list[str],
    models_index: dict[str, dict[str, Any]],
    icons: dict[str, str],
    object_names: dict[str, str],
) -> dict[str, Any]:
    """Build inline model vocabularies from raw object index data."""
    object_index: dict[str, Any] = {}
    for object_type in object_scope:
        index_name = object_names[object_type]
        metadata = {
            "field": object_type,
            "icon": icons.get(object_type, ""),
            "name": index_name,
            "description": index_name,
            "model": True,
        }
        entries: dict[str, Any] = {}
        registry = models_index.get(object_type) or {}
        for _uuid, object_data in registry.items():
            entry: dict[str, Any] = {
                "name": object_data["name"],
                "model": True,
                "tlp": object_data["metadata"]["tlp"],
            }
            if object_data.get("criticality") is not None:
                entry["criticality"] = object_data.get("criticality")
            aliases = object_data.get("actor", {}).get("aliases")
            if aliases is not None:
                entry["aliases"] = aliases
            match object_type:
                case "tvm":
                    description = object_data.get("threat", {}).get("description")
                case "dom":
                    description = object_data.get("objective", {}).get("description")
                    entry["criticality"] = object_data.get("objective", {}).get("priority")
                case "mdr":
                    description = object_data.get("description") or ""
                case _:
                    description = ""
            entry["description"] = description
            entry = {k: v for k, v in entry.items() if v is not None}
            entry = {
                k: v.replace("\n ", " ") if isinstance(v, str) else v for k, v in entry.items()
            }
            entries[_uuid] = entry
            if object_type == "dom":
                for signal in object_data.get("objective", {}).get("signals", []):
                    signal_uuid = signal["uuid"]
                    signal_entry = {
                        "name": object_data["name"] + "::" + signal["name"],
                        "model": True,
                        "tide.object.parent": _uuid,
                        "tlp": object_data["metadata"]["tlp"],
                        "criticality": signal["severity"],
                        "description": signal["description"],
                    }
                    signal_entry = {k: v for k, v in signal_entry.items() if v is not None}
                    signal_entry = {
                        k: v.replace("\n ", " ") if isinstance(v, str) else v
                        for k, v in signal_entry.items()
                    }
                    entries[signal_uuid] = signal_entry
        object_index[object_type] = {"metadata": metadata, "entries": entries}
    if "dom" not in object_index and "dom" in object_names:
        object_index["dom"] = _empty_model_vocabulary("dom", icons, object_names)
    return object_index


def run() -> None:
    """Generate object vocabularies and write to configured index path."""
    index = IndexManager.load()
    config = index["configurations"]
    global_config = config["global"]
    doc_config = config.get("documentation", {})
    paths = IndexManager.return_paths(tier="tide")
    index_path = Path(paths["tide_indexes"])
    index_name = global_config["indexes"]["objects"]
    icons = doc_config.get("icons", {})
    object_names = doc_config.get("object_names", {})
    object_index = build_object_vocabularies(
        object_scope=global_config.get("objects", []),
        models_index=index["objects"],
        icons=icons,
        object_names=object_names,
    )
    output = index_path / index_name
    output.write_text(json.dumps(object_index, indent=4), encoding="utf-8")
