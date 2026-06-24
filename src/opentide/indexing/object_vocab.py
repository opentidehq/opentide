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
            if not isinstance(object_data, dict):
                continue
            name = object_data.get("name")
            obj_meta = object_data.get("metadata")
            if not name or not isinstance(obj_meta, dict):
                continue
            entry: dict[str, Any] = {
                "name": name,
                "model": True,
                "tlp": obj_meta.get("tlp", ""),
            }
            if object_data.get("criticality") is not None:
                entry["criticality"] = object_data.get("criticality")
            actor = object_data.get("actor")
            if isinstance(actor, dict):
                aliases = actor.get("aliases")
                if aliases is not None:
                    entry["aliases"] = aliases

            match object_type:
                case "threat":
                    threat = object_data.get("threat")
                    description = threat.get("description") if isinstance(threat, dict) else ""
                case "objective":
                    objective = object_data.get("objective")
                    description = (
                        objective.get("description") if isinstance(objective, dict) else ""
                    )
                    if isinstance(objective, dict) and objective.get("priority") is not None:
                        entry["criticality"] = objective.get("priority")
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

            objective = object_data.get("objective") if object_type == "objective" else None

            if object_type == "objective" and isinstance(objective, dict):
                for signal in objective.get("signals") or []:
                    if not isinstance(signal, dict):
                        continue
                    signal_uuid = signal.get("uuid")
                    signal_name = signal.get("name")
                    if not signal_uuid or not signal_name:
                        continue
                    signal_entry = {
                        "name": f"{name}::{signal_name}",
                        "model": True,
                        "tide.object.parent": _uuid,
                        "tlp": obj_meta.get("tlp", ""),
                        "criticality": signal.get("severity"),
                        "description": signal.get("description"),
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
