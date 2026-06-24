import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from opentide.core.logging import get_logger, is_debug_enabled
from opentide.core.registry import OpenTide
from opentide.deployment import GitRepository

logger = get_logger(__name__)


@dataclass
class RevisionTracker:
    date: str
    message: str
    author: str
    commit: str


@dataclass
class RevisionIndexEntry:
    name: str
    object: str
    description: str
    revisions: dict[str, RevisionTracker]


class RevisionIndexer:
    def __init__(self):
        self.INDEX_PATH = Path(OpenTide.Configurations.Global.Paths.Tide.tide_indexes)
        self.OBJECT_SCOPE = OpenTide.Configurations.Global.objects
        self.OBJECT_NAMES = OpenTide.Configurations.Documentation.object_names
        self.INDEX_NAME = OpenTide.Configurations.Global.indexes.revisions
        self.INDEX_PATH = self.INDEX_PATH / self.INDEX_NAME
        if not os.path.exists(self.INDEX_PATH):
            with open(self.INDEX_PATH, "w+", encoding="utf-8") as index_file:
                json.dump({}, index_file)
        with open(self.INDEX_PATH, encoding="utf-8") as index_file:
            self.RAW_REVISIONS_INDEX = json.load(index_file)
        self.REVISIONS_INDEX = self._load_revision_index(self.RAW_REVISIONS_INDEX)

    def run(self):
        new_index = self._create_index()
        if is_debug_enabled():
            logger.debug("revision_index_preview", index=new_index)
        new_index = {k: asdict(v) for k, v in new_index.items()}
        self._export(new_index)

    def _load_revision_index(self, revisions_index: dict) -> dict[str, RevisionIndexEntry]:
        revisions_index = revisions_index.copy()
        parsed_index = dict()
        for entry in revisions_index:
            tracked_revisions = revisions_index[entry].pop("revisions")
            parsed_revisions = dict()
            try:
                for revision in tracked_revisions:
                    parsed_revisions[revision] = RevisionTracker(**tracked_revisions[revision])
            except Exception:
                logger.critical("unparsable_tracked_revisions_entries")
                raise Exception
            try:
                parsed_index[entry] = RevisionIndexEntry(
                    **revisions_index[entry], revisions=parsed_revisions
                )
            except Exception:
                logger.critical("unparsable_object_revisions_entry")
                raise Exception
        return parsed_index

    def _new_revision(self, object_author: str = "") -> RevisionTracker:
        commit_details = GitRepository().last_commit_details
        return RevisionTracker(
            date=datetime.today().strftime("%Y-%m-%d"),
            message=commit_details.message,
            author=commit_details.author,
            commit=commit_details.sha,
        )

    def _create_entry(self, object: str, object_type: str):
        object_data = OpenTide.Models.Index[object_type][object]
        object_version = str(object_data.get("metadata", {}).get("version"))
        if not object_version:
            logger.critical("missing_object_version_can_t_proceed")
            raise Exception
        if existing_entry := self.REVISIONS_INDEX.get(object):
            if object_version not in existing_entry.revisions:
                existing_entry.revisions[object_version] = self._new_revision()
                return existing_entry
            else:
                return existing_entry
        else:
            object_type_name = self.OBJECT_NAMES[object_type]
            name = object_data["name"]
            match object_type:
                case "threat":
                    description = object_data.get("threat", {}).get("description")
                case "objective":
                    description = object_data.get("objective", {}).get("description")
                case "rule":
                    description = object_data.get("description") or ""
            return RevisionIndexEntry(
                name=name,
                object=object_type_name,
                description=description,
                revisions={object_version: self._new_revision()},
            )

    def _create_index(self) -> dict[str, RevisionIndexEntry]:
        updated_index = dict()
        for object_type in self.OBJECT_SCOPE:
            object_index = OpenTide.Models.Index.get(object_type)
            if not object_index:
                logger.error(
                    "could_not_find_a_current_indexable_set_of_opentide_object_for_the_type",
                    detail=object_type,
                )
                continue
            for object in object_index:
                updated_index[object] = self._create_entry(object, object_type)
        return updated_index

    def _export(self, index: dict):
        with open(self.INDEX_PATH, "w+", encoding="utf-8") as export:
            export.write("")
            json.dump(index, export, indent=4)


if __name__ == "__main__":
    RevisionIndexer().run()
