"""Typed vocabulary models, loader, and YAML validation."""

from __future__ import annotations
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any
import structlog

logger = structlog.get_logger("opentide.generation.vocabulary")
VOCABULARY_YAML_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["name", "field", "keys"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "field": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "icon": {"type": "string"},
        "model": {"type": "boolean"},
        "keys": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "object", "anyOf": [{"required": ["id"]}, {"required": ["name"]}]},
        },
        "stages": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "icon": {"type": "string"},
                },
            },
        },
    },
}


class VocabularyLoadError(Exception):
    """Raised when a vocabulary definition cannot be loaded or validated."""


def normalize_stages(stages: str | list[str] | None) -> list[str]:
    """Normalise ``tide.vocab.stages`` to a list of stage identifiers."""
    if stages is None:
        return []
    if isinstance(stages, str):
        return [stages]
    return list(stages)


def entry_key_field(*, model: bool) -> str:
    """Return the canonical key field for vocabulary entries."""
    return "id" if model else "name"


@dataclass(frozen=True)
class VocabularyMetadata:
    name: str
    field: str = ""
    description: str = ""
    icon: str = ""
    model: bool = False
    stages: tuple[Mapping[str, Any], ...] = ()
    extra: Mapping[str, Any] = dc_field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        if key in ("name", "field", "description", "icon", "model", "stages", "extra"):
            value = getattr(self, key)
            if key == "stages":
                return list(value) if value else default
            if value not in (None, "", False, ()):
                return value
        return self.extra.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "description": self.description,
            "icon": self.icon,
            "model": self.model,
            **dict(self.extra),
        }
        if self.stages:
            payload["stages"] = [dict(stage) for stage in self.stages]
        return payload


@dataclass(frozen=True)
class VocabularyEntry:
    name: str
    description: str = ""
    icon: str = ""
    link: str = ""
    stages: tuple[str, ...] = ()
    extra: Mapping[str, Any] = dc_field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        if key == "name":
            return self.name
        if key == "description":
            return self.description
        if key == "icon":
            return self.icon
        if key == "link":
            return self.link
        if key == "tide.vocab.stages":
            return list(self.stages)
        return self.extra.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self.as_dict()

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "description": self.description,
            "icon": self.icon,
            "link": self.link,
            **dict(self.extra),
        }
        if self.stages:
            payload["tide.vocab.stages"] = list(self.stages)
        return payload


@dataclass(frozen=True)
class VocabularyDefinition:
    metadata: VocabularyMetadata
    entries: dict[str, VocabularyEntry]

    def to_index_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "entries": {key: entry.as_dict() for key, entry in self.entries.items()},
        }


def _validate_yaml_structure(raw: Mapping[str, Any], *, source: str) -> None:
    if not isinstance(raw, Mapping):
        raise VocabularyLoadError(f"Vocabulary YAML must be a mapping: {source}")
    for required in ("name", "field", "keys"):
        if required not in raw:
            raise VocabularyLoadError(
                f"Missing required key '{required}' in vocabulary YAML: {source}"
            )
    keys = raw["keys"]
    if not isinstance(keys, list):
        raise VocabularyLoadError(f"Vocabulary 'keys' must be a list: {source}")
    for index, entry in enumerate(keys):
        if not isinstance(entry, Mapping):
            raise VocabularyLoadError(f"Malformed vocabulary entry at index {index} in {source}")
        if "id" not in entry and "name" not in entry:
            raise VocabularyLoadError(
                f"Vocabulary entry at index {index} missing 'id' or 'name' in {source}"
            )


def parse_yaml_vocabulary(raw: Mapping[str, Any], *, source: str = "") -> VocabularyDefinition:
    """Parse a vocabulary YAML document into a typed definition."""
    _validate_yaml_structure(raw, source=source)
    metadata_raw = {key: value for key, value in raw.items() if key not in ("field", "keys")}
    is_model = bool(metadata_raw.get("model"))
    entries: dict[str, VocabularyEntry] = {}
    for index, entry_data in enumerate(raw["keys"]):
        if not isinstance(entry_data, Mapping):
            logger.warning(
                "event", detail=f"Skipping malformed vocabulary entry at index {index}", arg0=source
            )
            continue
        key_name = entry_data.get("id") if is_model else entry_data.get("name")
        if not key_name:
            logger.warning(
                "event",
                detail=f"Skipping vocabulary entry missing key field in {source}",
                context_1=f"index={index}",
            )
            continue
        try:
            entry = _build_entry(entry_data, fallback_name=str(key_name))
        except VocabularyLoadError as exc:
            logger.warning("event", detail=str(exc), arg0=source, advice=f"entry={key_name}")
            continue
        entries[str(key_name)] = entry
    metadata = _build_metadata(metadata_raw, field=str(raw["field"]))
    return VocabularyDefinition(metadata=metadata, entries=entries)


def _build_metadata(raw: Mapping[str, Any], *, field: str) -> VocabularyMetadata:
    known = {"name", "description", "icon", "model", "stages"}
    stages_raw = raw.get("stages") or []
    stages = tuple((dict(stage) for stage in stages_raw if isinstance(stage, Mapping)))
    extra = {key: value for key, value in raw.items() if key not in known}
    return VocabularyMetadata(
        name=str(raw.get("name", "")),
        field=field,
        description=str(raw.get("description", "")),
        icon=str(raw.get("icon", "")),
        model=bool(raw.get("model")),
        stages=stages,
        extra=extra,
    )


def _build_entry(entry_data: Mapping[str, Any], *, fallback_name: str) -> VocabularyEntry:
    reserved = {"name", "description", "icon", "link", "tide.vocab.stages"}
    stages = normalize_stages(entry_data.get("tide.vocab.stages"))
    extra = {key: value for key, value in entry_data.items() if key not in reserved}
    return VocabularyEntry(
        name=str(entry_data.get("name", fallback_name)),
        description=str(entry_data.get("description", "")),
        icon=str(entry_data.get("icon", "")),
        link=str(entry_data.get("link", "")),
        stages=tuple(stages),
        extra=extra,
    )


class VocabularyLoader:
    """Load and validate vocabulary definitions from index-shaped dicts."""

    @staticmethod
    def load(raw: Mapping[str, Any], *, source: str = "") -> VocabularyDefinition:
        if "metadata" not in raw:
            raise VocabularyLoadError(
                f"Missing 'metadata' in vocabulary definition{(f' ({source})' if source else '')}"
            )
        if "entries" not in raw:
            raise VocabularyLoadError(
                f"Missing 'entries' in vocabulary definition{(f' ({source})' if source else '')}"
            )
        metadata_raw = raw["metadata"]
        if not isinstance(metadata_raw, Mapping):
            raise VocabularyLoadError(f"Invalid metadata block in vocabulary {source}")
        field_name = str(metadata_raw.get("field", source))
        metadata = _build_metadata(metadata_raw, field=field_name)
        entries: dict[str, VocabularyEntry] = {}
        entries_raw = raw["entries"]
        if not isinstance(entries_raw, Mapping):
            raise VocabularyLoadError(f"Invalid entries block in vocabulary {source}")
        for key, entry_data in entries_raw.items():
            if not isinstance(entry_data, Mapping):
                logger.warning(
                    "event", detail=f"Skipping malformed vocabulary entry '{key}'", arg0=source
                )
                continue
            try:
                entries[str(key)] = _build_entry(entry_data, fallback_name=str(key))
            except VocabularyLoadError as exc:
                logger.warning("event", detail=str(exc), arg0=source, advice=f"entry={key}")
        return VocabularyDefinition(metadata=metadata, entries=entries)

    @staticmethod
    def load_from_yaml_file(path: Path) -> VocabularyDefinition:
        import yaml

        source = str(path)
        try:
            raw = yaml.safe_load(path.open(encoding="utf-8"))
        except Exception as exc:
            raise VocabularyLoadError(f"Could not read vocabulary YAML {source}: {exc}") from exc
        if not raw:
            raise VocabularyLoadError(f"Empty vocabulary YAML file: {source}")
        return parse_yaml_vocabulary(raw, source=source)

    @staticmethod
    def load_index(raw_vocabs: Mapping[str, Any] | None) -> dict[str, VocabularyDefinition]:
        """Load all vocabularies from an index vocabs mapping with per-file error boundaries."""
        if not raw_vocabs:
            logger.error("vocabulary_index_is_missing_or_empty")
            return {}
        loaded: dict[str, VocabularyDefinition] = {}
        for name, data in raw_vocabs.items():
            try:
                loaded[name] = VocabularyLoader.load(data, source=name)
            except VocabularyLoadError as exc:
                logger.error("operation_failed", detail=str(exc))
        return loaded
