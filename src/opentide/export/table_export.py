"""Export object catalog to ``.opentide/exports/objects.export.json``."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide
from opentide.generation.framework import childs, get_vocab_entry, parents

logger = get_logger(__name__)


@dataclass
class TableEntry:
    uuid: str
    name: str
    type: str
    tlp: str
    description: str
    version: str
    created: str
    modified: str
    childs: str
    parents: str
    chaining: str
    actors: str
    attack: str


class TableExporter:
    def __init__(self) -> None:
        OpenTide.initialise()
        self.exports_path = Path(OpenTide.Configurations.Global.Paths.Tide.exports)
        self.object_scope = OpenTide.Configurations.Global.objects
        self.object_names = OpenTide.Configurations.Documentation.object_names
        self.export_name = OpenTide.Configurations.Global.exports.objects
        self.export_path = self.exports_path / self.export_name

    def run(self) -> None:
        dataset = [asdict(entry) for entry in self._create_dataset()]
        self.exports_path.mkdir(parents=True, exist_ok=True)
        self.export_path.write_text(
            json.dumps(dataset, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _flatten_actors(self, actors: Sequence[Any]) -> list[str]:
        """Resolve ``threat.actors`` vocab keys (or legacy dicts) to display names."""

        def _identifier(actor: Any) -> str:
            if isinstance(actor, dict):
                raw = actor.get("name") or actor.get("id") or ""
            else:
                raw = actor
            token = str(raw).split(" #", 1)[0].strip()
            if token.startswith("actor::"):
                return token.split("::", 1)[1]
            return token

        def _enrich_actor_name(identifier: str) -> str:
            if not identifier:
                return ""
            actor_data = get_vocab_entry("actors", identifier)
            if isinstance(actor_data, dict):
                name = actor_data.get("name")
                if name:
                    return str(name)
            return identifier

        items: Sequence[Any] = [actors] if isinstance(actors, str) else actors
        return [_enrich_actor_name(_identifier(actor)) for actor in items]

    def _flatten_chaining(self, chains: list[dict[str, Any]]) -> dict[str, list[str]]:
        flat_chains: dict[str, list[str]] = {}
        for chain in chains:
            flat_chains.setdefault(chain["relation"], [])
            flat_chains[chain["relation"]].append(chain["vector"])
        return flat_chains

    def _create_entry(self, object_uuid: str, object_type: str) -> TableEntry:
        object_data = OpenTide.Models.Index[object_type][object_uuid]
        name = object_data["name"]
        object_type_name = self.object_names[object_type]
        metadata = object_data["metadata"]
        tlp = metadata["tlp"]
        version = str(metadata["version"])
        created = metadata["created"]
        modified = metadata["modified"]
        actors = attack = chaining = ""
        object_childs = childs(object_uuid)
        object_childs = ", ".join(object_childs) if object_childs else ""
        object_parents = parents(object_uuid) or ""
        object_parents = ", ".join(object_parents) if object_parents else ""
        description = ""
        if object_type == "threat":
            description = str(object_data.get("threat", {}).get("description", ""))
            chains = object_data["threat"].get("chaining") or ""
            if chains:
                chaining = str(self._flatten_chaining(chains))
            actors_raw = object_data["threat"].get("actors") or ""
            if actors_raw:
                actors = ", ".join(self._flatten_actors(actors_raw))
            attack = ", ".join(object_data["threat"]["att&ck"])
        elif object_type == "objective":
            description = str(object_data.get("objective", {}).get("description", ""))
            if techniques := object_data["objective"].get("att&ck"):
                attack = ", ".join(techniques)
        elif object_type == "rule":
            description = str(object_data.get("description", ""))
        return TableEntry(
            uuid=object_uuid,
            name=name,
            type=object_type_name,
            tlp=tlp,
            description=description,
            version=version,
            created=created,
            modified=modified,
            childs=object_childs,
            parents=object_parents,
            chaining=chaining,
            actors=actors,
            attack=attack,
        )

    def _create_dataset(self) -> Sequence[TableEntry]:
        dataset: list[TableEntry] = []
        for object_type in self.object_scope:
            object_index = OpenTide.Models.Index.get(object_type) or {}
            if not object_index:
                logger.debug(
                    "object_index_empty",
                    object_type=object_type,
                )
                continue
            for object_uuid in object_index:
                dataset.append(self._create_entry(object_uuid, object_type))
        return dataset


if __name__ == "__main__":
    TableExporter().run()
