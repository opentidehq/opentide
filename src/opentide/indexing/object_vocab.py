"""Object vocabulary generation — inline replacement for objects_indexer."""

from __future__ import annotations

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
                case "threat":
                    description = object_data.get("threat", {}).get("description")
                case "objective":
                    description = object_data.get("objective", {}).get("description")
                    entry["criticality"] = object_data.get("objective", {}).get("priority")
                case "rule":
                    description = object_data.get("description") or ""
                case _:
                    description = ""

            entry["description"] = description
            entry = {k: v for k, v in entry.items() if v is not None}
            entry = {
                k: v.replace("\n ", " ") if isinstance(v, str) else v for k, v in entry.items()
            }
            entries[_uuid] = entry

            if object_type == "objective":
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

    if "objective" not in object_index and "objective" in object_names:
        object_index["objective"] = _empty_model_vocabulary("objective", icons, object_names)

    return object_index


def run() -> dict[str, Any]:
    """Build object vocabularies from the current in-memory index (no disk write)."""
    index = IndexManager.load()
    config = index["configurations"]
    global_config = config["global"]
    doc_config = config.get("documentation", {})
    icons = doc_config.get("icons", {})
    object_names = doc_config.get("object_names", {})

    return build_object_vocabularies(
        object_scope=global_config.get("objects", []),
        models_index=index["objects"],
        icons=icons,
        object_names=object_names,
    )
